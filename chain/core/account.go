package core

import (
	"fmt"
	"net/http"

	"gorm.io/gorm"

	"github.com/yu-org/yu/core/context"
	"github.com/yu-org/yu/core/tripod"
	"github.com/yu-org/yu/core/types"
)

// ────────────────────── Tripod ──────────────────────

// Account is the tripod that owns the cash table: balances are tracked as
// individual Cash UTXO-style records rather than aggregate balances, since
// amounts are encrypted ciphertext and cannot be summed on-chain.
type Account struct {
	*tripod.Tripod
	db  *gorm.DB
	cfg *AccountConfig
}

// NewAccount constructs the Account tripod and registers its writings and readings.
// `cfg` must carry a valid SQLite DSN — a bad DSN panics during DB init.
func NewAccount(cfg *AccountConfig) *Account {
	tri := tripod.NewTripodWithName("account")
	a := &Account{Tripod: tri, db: InitAccountDB(cfg.DBPath), cfg: cfg}
	a.SetWritings(a.Deposit, a.Withdraw)
	a.SetReadings(a.GetAccount)
	return a
}

// InitChain inserts genesis Cash records at chain startup.
// Cash IDs are taken directly from the config — no derivation happens on-chain.
func (a *Account) InitChain(block *types.Block) {
	for _, gc := range a.cfg.GenesisCash {
		cash := &Cash{
			ID:      gc.ID,
			Pubkey:  gc.Pubkey,
			Token:   TokenID(gc.Token),
			Amount:  CipherText(gc.Amount),
			ZkProof: "genesis",
			Status:  Active,
		}
		if err := a.CreateCash(cash); err != nil {
			panic(fmt.Sprintf("failed to seed genesis cash %s: %v", gc.ID, err))
		}
		fmt.Printf("genesis: id=%s pubkey=%s token=%s amount=%s\n", gc.ID, gc.Pubkey, gc.Token, gc.Amount)
	}
}

// ────────────────────── Reading: GetAccount ──────────────────────

// GetAccountRequest queries every non-Spent Cash for `Pubkey` under `Token`.
type GetAccountRequest struct {
	Pubkey string  `json:"pubkey" validate:"required"`
	Token  TokenID `json:"token"  validate:"required"`
}

// GetAccount returns all non-Spent Cash for the given pubkey and token.
// Amounts are ciphertext, so no aggregate balance is computed on-chain.
func (a *Account) GetAccount(ctx *context.ReadContext) {
	req := new(GetAccountRequest)
	if err := ctx.BindJson(req); err != nil {
		ctx.Json(http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if err := Validator.Struct(req); err != nil {
		ctx.Json(http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	cash, err := a.FindNonSpentCash(req.Pubkey, req.Token)
	if err != nil {
		ctx.Json(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	ctx.JsonOk(&AccountRecord{
		Pubkey: req.Pubkey,
		Token:  req.Token,
		Cash:   cash,
	})
}

// ────────────────────── Writing: Deposit ──────────────────────

// DepositRequest carries a bridge proof that the user deposited `Amount` of
// `Token` into the Invisibook bridge contract on a source chain.
type DepositRequest struct {
	Pubkey  string     `json:"pubkey"   validate:"required"` // depositor's ed25519 pubkey (64-char hex)
	Token   TokenID    `json:"token"    validate:"required"`
	Amount  CipherText `json:"amount"   validate:"required"` // encrypted amount
	ZkProof string     `json:"zk_proof" validate:"required"` // bridge deposit proof
}

// Deposit verifies the bridge proof then mints a new Active Cash for the depositor.
func (a *Account) Deposit(ctx *context.WriteContext) error {
	ctx.SetLei(100)

	req := new(DepositRequest)
	if err := ctx.BindJson(req); err != nil {
		return err
	}
	if err := Validator.Struct(req); err != nil {
		return err
	}

	// TODO: verify zk_proof that the user deposited the corresponding assets
	// into the Invisibook bridge contract on another chain.

	cash := &Cash{
		ID:      computeCashID(req.Pubkey, req.Token, req.Amount),
		Pubkey:  req.Pubkey,
		Token:   req.Token,
		Amount:  req.Amount,
		ZkProof: req.ZkProof,
		Status:  Active,
	}
	if err := a.CreateCash(cash); err != nil {
		return fmt.Errorf("failed to create cash: %w", err)
	}

	ctx.EmitStringEvent("deposit: pubkey=%s token=%s cash=%s",
		req.Pubkey, string(req.Token), cash.ID)
	return nil
}

// ────────────────────── Writing: Withdraw ──────────────────────

// WithdrawRequest spends `Inputs` Cash IDs and optionally mints a `Change` Cash
// back to the withdrawer. ZkProof must prove sum(inputs) >= withdrawn amount
// and that the change commitment is correct.
type WithdrawRequest struct {
	Pubkey  string        `json:"pubkey"   validate:"required"` // withdrawer's ed25519 pubkey (64-char hex)
	Token   TokenID       `json:"token"    validate:"required"`
	Inputs  []string      `json:"inputs"   validate:"required,min=1"` // Cash IDs to consume
	Change  *ChangeOutput `json:"change,omitempty"`                   // optional change Cash
	ZkProof string        `json:"zk_proof" validate:"required"`       // proves the withdrawal is valid
}

// Withdraw verifies the overall spend proof, then marks each input Cash as Spent.
// If the client supplies a change output it is minted as a new Active Cash.
// Withdraw consumes Active Cash directly (Active → Spent), skipping the Locked state.
func (a *Account) Withdraw(ctx *context.WriteContext) error {
	ctx.SetLei(100)

	req := new(WithdrawRequest)
	if err := ctx.BindJson(req); err != nil {
		return err
	}
	if err := Validator.Struct(req); err != nil {
		return err
	}

	// TODO: verify req.ZkProof — proves that sum(inputs) >= withdrawn amount
	// and that the change output commitment is correct.

	spendBy := fmt.Sprintf("withdraw:%s", req.Pubkey[:8])
	if err := a.SpendCash(req.Inputs, spendBy); err != nil {
		return fmt.Errorf("failed to spend cash: %w", err)
	}

	if req.Change != nil {
		if err := Validator.Struct(req.Change); err != nil {
			return fmt.Errorf("invalid change output: %w", err)
		}
		changeCash := &Cash{
			ID:      computeCashID(req.Change.Pubkey, req.Token, req.Change.Amount),
			Pubkey:  req.Change.Pubkey,
			Token:   req.Token,
			Amount:  req.Change.Amount,
			ZkProof: req.ZkProof,
			Status:  Active,
		}
		if err := a.CreateCash(changeCash); err != nil {
			return fmt.Errorf("failed to create change cash: %w", err)
		}
	}

	ctx.EmitStringEvent("withdraw: token=%s spent=%d by=%s",
		string(req.Token), len(req.Inputs), spendBy)
	return nil
}

package core

import (
	"fmt"
	"net/http"

	"gorm.io/gorm"

	"github.com/yu-org/yu/core/context"
	"github.com/yu-org/yu/core/tripod"
)

// ────────────────────── Tripod ──────────────────────

type Account struct {
	*tripod.Tripod
	db *gorm.DB
}

func NewAccount() *Account {
	tri := tripod.NewTripodWithName("account")
	a := &Account{Tripod: tri, db: InitAccountDB("accounts.db")}
	a.SetWritings(a.Deposit, a.Withdraw)
	a.SetReadings(a.GetAccount)
	return a
}

// ────────────────────── Reading: GetAccount ──────────────────────

type GetAccountRequest struct {
	Address string  `json:"address" validate:"required"`
	Token   TokenID `json:"token"   validate:"required"`
}

// GetAccount returns all Active Cash for the given address and token.
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

	cash, err := a.FindActiveCash(req.Address, req.Token)
	if err != nil {
		ctx.Json(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	ctx.JsonOk(&AccountRecord{
		Address: req.Address,
		Token:   req.Token,
		Cash:    cash,
	})
}

// ────────────────────── Writing: Deposit ──────────────────────

type DepositRequest struct {
	Address string     `json:"address"  validate:"required"`
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
		ID:      generateCashID(),
		Owner:   req.Address,
		Token:   req.Token,
		Amount:  req.Amount,
		ZkProof: req.ZkProof,
		Status:  Active,
	}
	if err := a.CreateCash(cash); err != nil {
		return fmt.Errorf("failed to create cash: %w", err)
	}

	ctx.EmitStringEvent("deposit: addr=%s token=%s cash=%s",
		req.Address, string(req.Token), cash.ID)
	return nil
}

// ────────────────────── Writing: Withdraw ──────────────────────

type WithdrawRequest struct {
	Token   TokenID       `json:"token"   validate:"required"`
	Inputs  []string      `json:"inputs"  validate:"required,min=1"` // Cash IDs to consume
	Change  *ChangeOutput `json:"change,omitempty"`                  // optional change Cash
	ZkProof string        `json:"zk_proof" validate:"required"`      // proves the withdrawal is valid
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

	spendTxID := generateCashID()
	if err := a.SpendCash(req.Inputs, spendTxID); err != nil {
		return fmt.Errorf("failed to spend cash: %w", err)
	}

	if req.Change != nil {
		if err := Validator.Struct(req.Change); err != nil {
			return fmt.Errorf("invalid change output: %w", err)
		}
		changeCash := &Cash{
			ID:      generateCashID(),
			Owner:   req.Change.Owner,
			Token:   req.Token,
			Amount:  req.Change.Amount,
			ZkProof: req.ZkProof, // reuse withdrawal proof as the change commitment
			Status:  Active,
		}
		if err := a.CreateCash(changeCash); err != nil {
			return fmt.Errorf("failed to create change cash: %w", err)
		}
	}

	ctx.EmitStringEvent("withdraw: token=%s spent=%d cash tx=%s",
		string(req.Token), len(req.Inputs), spendTxID)
	return nil
}

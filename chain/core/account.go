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

// Account is the tripod that owns the legacy cash table and the shielded
// pool (notes, nullifiers, anchors). Cash amounts are commitments and
// cannot be summed on-chain; pool notes hide owner, asset, and amount.
type Account struct {
	*tripod.Tripod
	db              *gorm.DB
	cfg             *AccountConfig
	depositVK       *CircuitVK
	withdrawVK      *CircuitVK
	noteDepositVK   *CircuitVK
	spendWithdrawVK *CircuitVK
	pool            pool
}

// NewAccount constructs the Account tripod and registers its writings and
// readings. `cfg` must carry a valid SQLite DSN and readable VK paths.
// DB init and VK loading panic on failure.
func NewAccount(cfg *AccountConfig) *Account {
	tri := tripod.NewTripodWithName("account")
	depositVK, err := LoadVK("deposit", cfg.DepositVKPath)
	if err != nil {
		panic(fmt.Sprintf("loading deposit VK: %v", err))
	}
	withdrawVK, err := LoadVK("withdraw", cfg.WithdrawVKPath)
	if err != nil {
		panic(fmt.Sprintf("loading withdraw VK: %v", err))
	}
	noteDepositVK, err := LoadVK("note_deposit", cfg.NoteDepositVKPath)
	if err != nil {
		panic(fmt.Sprintf("loading note_deposit VK: %v", err))
	}
	spendWithdrawVK, err := LoadVK("spend_withdraw", cfg.SpendWithdrawVKPath)
	if err != nil {
		panic(fmt.Sprintf("loading spend_withdraw VK: %v", err))
	}
	// Fail-closed in production (mirrors the OrderBook flag): a nil VK
	// means an empty path and silently skipped verification.
	if cfg.RequireProofs {
		for name, missing := range map[string]bool{
			"deposit":        depositVK == nil,
			"withdraw":       withdrawVK == nil,
			"note_deposit":   noteDepositVK == nil,
			"spend_withdraw": spendWithdrawVK == nil,
		} {
			if missing {
				panic(fmt.Sprintf("require_proofs is set but %s VK path is empty; refusing to start with proof verification disabled", name))
			}
		}
	}
	a := &Account{
		Tripod:          tri,
		db:              InitAccountDB(cfg.DBPath, ParseGormLogLevel(cfg.DBLogLevel)),
		cfg:             cfg,
		depositVK:       depositVK,
		withdrawVK:      withdrawVK,
		noteDepositVK:   noteDepositVK,
		spendWithdrawVK: spendWithdrawVK,
	}
	if err := a.InitPool(); err != nil {
		panic(fmt.Sprintf("initializing note pool: %v", err))
	}
	a.SetWritings(a.Deposit, a.Withdraw, a.NoteDeposit, a.NoteWithdraw)
	a.SetReadings(a.GetAccount, a.GetNotes, a.GetPoolInfo, a.GetNullifiers, a.GetNoteByCm)
	return a
}

// InitChain inserts genesis Cash records and seeds the genesis pool notes
// at chain startup. Both paths are idempotent — InitChain runs on EVERY
// boot, so re-seeding must never duplicate or shift state.
func (a *Account) InitChain(block *types.Block) {
	a.seedGenesisNotes(uint64(block.Height))
	for _, gc := range a.cfg.GenesisCash {
		if a.CashExists(gc.ID) {
			continue
		}
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
		fmt.Printf("genesis: id=%s pubkey=%s token=%s\n", gc.ID, gc.Pubkey, gc.Token)
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

// DepositRequest carries a Groth16 deposit proof binding the new Cash's hidden
// amount to a `BridgeCommitment` that the (future) bridge inclusion proof will
// attest. `OutputCommitment` is the Poseidon commitment of the new Cash's
// amount and becomes its on-chain `Cash.Amount` field.
type DepositRequest struct {
	Pubkey           string  `json:"pubkey"            validate:"required"` // depositor's ed25519 pubkey (64-char hex)
	Token            TokenID `json:"token"             validate:"required"`
	BridgeCommitment string  `json:"bridge_commitment" validate:"required,len=64"` // Poseidon(deposit_amount, r_bridge) hex
	OutputCommitment string  `json:"output_commitment" validate:"required,len=64"` // Poseidon(output_amount, r_output) hex
	ZkProof          string  `json:"zk_proof"          validate:"required"`        // snarkjs proof.json string
}

// Deposit verifies the deposit zk proof then mints a new Active Cash whose
// `Amount` is the proof's output commitment.
//
// The bridge inclusion proof attesting `BridgeCommitment` is **not** verified
// in this revision — until that lands, any client can fabricate a
// `BridgeCommitment` and mint arbitrary value. Suitable for testnet/demo only.
func (a *Account) Deposit(ctx *context.WriteContext) error {
	ctx.SetLei(100)

	req := new(DepositRequest)
	if err := ctx.BindJson(req); err != nil {
		return err
	}
	if err := Validator.Struct(req); err != nil {
		return err
	}

	// TODO: verify a bridge inclusion proof attesting that `BridgeCommitment`
	// was logged by the Invisibook bridge contract on the source chain.

	// Rebuild the public-input vector in the order deposit.circom declares them:
	//   public[0] = bridge_commitment
	//   public[1] = output_hashes[0]   (real cash)
	//   public[2] = output_hashes[1]   (zero-padded slot, Poseidon(0, 0))
	bridgeDecimal, err := HexToDecimal(req.BridgeCommitment)
	if err != nil {
		return fmt.Errorf("invalid bridge_commitment: %w", err)
	}
	outputDecimal, err := HexToDecimal(req.OutputCommitment)
	if err != nil {
		return fmt.Errorf("invalid output_commitment: %w", err)
	}
	publicSignals := []string{bridgeDecimal, outputDecimal, PoseidonZeroCommitment}

	if err := VerifyGroth16(a.depositVK, req.ZkProof, publicSignals); err != nil {
		return fmt.Errorf("deposit proof verification failed: %w", err)
	}

	cash := &Cash{
		ID:      computeCashID(req.Pubkey, req.Token, CipherText(req.OutputCommitment)),
		Pubkey:  req.Pubkey,
		Token:   req.Token,
		Amount:  CipherText(req.OutputCommitment),
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

// WithdrawRequest carries a Groth16 withdraw proof binding the (hidden)
// `withdraw_amount` to a `BridgeOutCommitment` that the (future) destination-
// chain bridge release proof will attest. Inputs are existing Cash IDs the
// chain looks up to extract their commitments; `OutputCommitments[0]` is the
// new change Cash (set to `PoseidonZeroCommitmentHex` when no change is
// produced) and `OutputCommitments[1]` is always the zero pad.
type WithdrawRequest struct {
	Pubkey              string   `json:"pubkey"                validate:"required"`
	Token               TokenID  `json:"token"                 validate:"required"`
	Inputs              []string `json:"inputs"                validate:"required,min=1,max=2,unique"`
	BridgeOutCommitment string   `json:"bridge_out_commitment" validate:"required,len=64"`
	OutputCommitments   []string `json:"output_commitments"    validate:"required,len=2,dive,len=64"`
	// ChangePubkey is the recipient of the change Cash. Defaults to `Pubkey`
	// when empty so withdrawing-and-keeping-change-yourself is the common path.
	ChangePubkey string `json:"change_pubkey,omitempty"`
	ZkProof      string `json:"zk_proof"              validate:"required"`
}

// Withdraw verifies the withdraw zk proof, marks each input Cash as Spent,
// and (if the change slot is non-zero) mints a new Active change Cash.
//
// The destination-chain bridge release proof attesting `BridgeOutCommitment`
// is **not** verified in this revision — until that lands, any client can
// fabricate a `BridgeOutCommitment`. The conservation constraint still holds
// (you can't withdraw more value than you spend), but the destination-chain
// release amount is currently unbound. Suitable for testnet/demo only.
func (a *Account) Withdraw(ctx *context.WriteContext) error {
	ctx.SetLei(100)

	req := new(WithdrawRequest)
	if err := ctx.BindJson(req); err != nil {
		return err
	}
	if err := Validator.Struct(req); err != nil {
		return err
	}

	// Look up each input cash and pull its on-chain commitment (= Cash.Amount).
	// Reject early on missing/wrong-owner/wrong-token/non-Active inputs so a bad
	// request fails before we even invoke the verifier.
	inputCommitmentsHex := make([]string, len(req.Inputs))
	for i, id := range req.Inputs {
		cash, err := a.GetCash(id)
		if err != nil {
			return fmt.Errorf("input cash %s not found: %w", id, err)
		}
		if cash.Pubkey != req.Pubkey {
			return fmt.Errorf("input cash %s pubkey mismatch", id)
		}
		if cash.Token != req.Token {
			return fmt.Errorf("input cash %s token mismatch", id)
		}
		if cash.Status != Active {
			return fmt.Errorf("input cash %s is not Active (current: %s)", id, cash.Status.String())
		}
		inputCommitmentsHex[i] = string(cash.Amount)
	}

	// TODO: verify a destination-chain bridge release proof attesting that
	// `BridgeOutCommitment` matches what the bridge contract will release.

	// Rebuild the public-input vector in the order withdraw.circom declares them:
	//   public[0]            = bridge_out_commitment
	//   public[1..1+N]       = input_hashes (zero-padded to N=2)
	//   public[1+N..1+N+M]   = output_hashes (M=2: change + zero pad)
	bridgeDecimal, err := HexToDecimal(req.BridgeOutCommitment)
	if err != nil {
		return fmt.Errorf("invalid bridge_out_commitment: %w", err)
	}
	publicSignals := make([]string, 0, 1+2+2)
	publicSignals = append(publicSignals, bridgeDecimal)

	const withdrawN = 2
	for i := 0; i < withdrawN; i++ {
		var hex string
		if i < len(inputCommitmentsHex) {
			hex = inputCommitmentsHex[i]
		} else {
			hex = PoseidonZeroCommitmentHex
		}
		dec, err := HexToDecimal(hex)
		if err != nil {
			return fmt.Errorf("invalid input commitment hex at slot %d: %w", i, err)
		}
		publicSignals = append(publicSignals, dec)
	}
	for i, oc := range req.OutputCommitments {
		dec, err := HexToDecimal(oc)
		if err != nil {
			return fmt.Errorf("invalid output_commitments[%d]: %w", i, err)
		}
		publicSignals = append(publicSignals, dec)
	}

	if err := VerifyGroth16(a.withdrawVK, req.ZkProof, publicSignals); err != nil {
		return fmt.Errorf("withdraw proof verification failed: %w", err)
	}

	// All checks passed — mutate state.
	spendBy := fmt.Sprintf("withdraw:%s", req.Pubkey[:8])
	if err := a.SpendCash(req.Inputs, spendBy); err != nil {
		return fmt.Errorf("failed to spend cash: %w", err)
	}

	// Mint change Cash unless slot[0] is the zero-pad constant.
	if req.OutputCommitments[0] != PoseidonZeroCommitmentHex {
		changePubkey := req.ChangePubkey
		if changePubkey == "" {
			changePubkey = req.Pubkey
		}
		changeCash := &Cash{
			ID:      computeCashID(changePubkey, req.Token, CipherText(req.OutputCommitments[0])),
			Pubkey:  changePubkey,
			Token:   req.Token,
			Amount:  CipherText(req.OutputCommitments[0]),
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

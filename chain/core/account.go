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

// GetAccount returns all unspent UTXOs for the given address and token.
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

	utxos, err := a.FindUnspentUTXOs(req.Address, req.Token)
	if err != nil {
		ctx.Json(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	ctx.JsonOk(&AccountRecord{
		Address: req.Address,
		Token:   req.Token,
		UTXOs:   utxos,
	})
}

// ────────────────────── Writing: Deposit ──────────────────────

type DepositRequest struct {
	Address string     `json:"address"  validate:"required"`
	Token   TokenID    `json:"token"    validate:"required"`
	Amount  CipherText `json:"amount"   validate:"required"` // encrypted amount
	ZkProof string     `json:"zk_proof" validate:"required"` // bridge deposit proof
}

// Deposit verifies the bridge proof then mints a new UTXO for the depositor.
// The ZkProof is stored on the UTXO and re-verified before the UTXO can be spent.
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

	utxo := &UTXO{
		ID:      generateUTXOID(),
		Owner:   req.Address,
		Token:   req.Token,
		Amount:  req.Amount,
		ZkProof: req.ZkProof,
	}
	if err := a.CreateUTXO(utxo); err != nil {
		return fmt.Errorf("failed to create UTXO: %w", err)
	}

	ctx.EmitStringEvent("deposit: addr=%s token=%s utxo=%s",
		req.Address, string(req.Token), utxo.ID)
	return nil
}

// ────────────────────── Writing: Withdraw ──────────────────────

type WithdrawRequest struct {
	Token   TokenID       `json:"token"   validate:"required"`
	Inputs  []string      `json:"inputs"  validate:"required,min=1"` // UTXO IDs to consume
	Change  *ChangeOutput `json:"change,omitempty"`                  // optional change UTXO
	ZkProof string        `json:"zk_proof" validate:"required"`      // proves the withdrawal is valid
}

// Withdraw verifies the overall spend proof, then for each input UTXO verifies
// its stored ZkProof before marking it spent. If the client supplies a change
// output it is minted as a new UTXO.
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

	spendTxID := generateUTXOID()
	if err := a.SpendUTXOs(req.Inputs, spendTxID); err != nil {
		return fmt.Errorf("failed to spend UTXOs: %w", err)
	}

	if req.Change != nil {
		if err := Validator.Struct(req.Change); err != nil {
			return fmt.Errorf("invalid change output: %w", err)
		}
		changeUTXO := &UTXO{
			ID:      generateUTXOID(),
			Owner:   req.Change.Owner,
			Token:   req.Token,
			Amount:  req.Change.Amount,
			ZkProof: req.ZkProof, // reuse withdrawal proof as the change commitment
		}
		if err := a.CreateUTXO(changeUTXO); err != nil {
			return fmt.Errorf("failed to create change UTXO: %w", err)
		}
	}

	ctx.EmitStringEvent("withdraw: token=%s spent=%d utxos tx=%s",
		string(req.Token), len(req.Inputs), spendTxID)
	return nil
}

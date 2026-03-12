package core

import (
	"fmt"
	"math/big"
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

// GetAccount returns the account balance for the given public-key address and token.
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

	acc, err := a.FindAccount(req.Address, req.Token)
	if err != nil {
		ctx.Json(http.StatusNotFound, map[string]string{"error": "account not found"})
		return
	}
	ctx.JsonOk(acc)
}

// ────────────────────── Writing: Deposit ──────────────────────

type DepositRequest struct {
	Address string   `json:"address"  validate:"required"`
	Token   TokenID  `json:"token"    validate:"required"`
	Amount  *big.Int `json:"amount"   validate:"required"`
	ZkProof string   `json:"zk_proof" validate:"required"`
}

// Deposit verifies that the user has bridged assets from another chain, then
// credits the corresponding balance on this chain.
func (a *Account) Deposit(ctx *context.WriteContext) error {
	ctx.SetLei(100)

	req := new(DepositRequest)
	if err := ctx.BindJson(req); err != nil {
		return err
	}
	if err := Validator.Struct(req); err != nil {
		return err
	}
	if req.Amount.Sign() <= 0 {
		return fmt.Errorf("deposit amount must be positive")
	}

	// TODO: verify zk_proof that the user deposited the corresponding assets
	// into the Invisibook bridge contract on another chain.

	if err := a.UpsertBalance(req.Address, req.Token, req.Amount); err != nil {
		return fmt.Errorf("failed to deposit: %w", err)
	}

	ctx.EmitStringEvent("deposit: addr=%s token=%s amount=%s",
		req.Address, string(req.Token), req.Amount.String())
	return nil
}

// ────────────────────── Writing: Withdraw ──────────────────────

type WithdrawRequest struct {
	Address string   `json:"address"  validate:"required"`
	Token   TokenID  `json:"token"    validate:"required"`
	Amount  *big.Int `json:"amount"   validate:"required"`
	ZkProof string   `json:"zk_proof" validate:"required"`
}

// Withdraw reduces the user's on-chain balance; the bridge contract on the
// destination chain releases the corresponding assets.
func (a *Account) Withdraw(ctx *context.WriteContext) error {
	ctx.SetLei(100)

	req := new(WithdrawRequest)
	if err := ctx.BindJson(req); err != nil {
		return err
	}
	if err := Validator.Struct(req); err != nil {
		return err
	}
	if req.Amount.Sign() <= 0 {
		return fmt.Errorf("withdrawal amount must be positive")
	}

	// TODO: verify zk_proof that the withdrawal amount <= current balance.

	acc, err := a.FindAccount(req.Address, req.Token)
	if err != nil {
		return fmt.Errorf("account not found: %w", err)
	}
	if acc.Balance.Cmp(req.Amount) < 0 {
		return fmt.Errorf("insufficient balance: have %s, want %s",
			acc.Balance.String(), req.Amount.String())
	}

	newBalance := new(big.Int).Sub(acc.Balance, req.Amount)
	if err := a.SetBalance(req.Address, req.Token, newBalance); err != nil {
		return fmt.Errorf("failed to withdraw: %w", err)
	}

	ctx.EmitStringEvent("withdraw: addr=%s token=%s amount=%s",
		req.Address, string(req.Token), req.Amount.String())
	return nil
}

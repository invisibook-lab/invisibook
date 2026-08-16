package core

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"net/http"

	"crypto/ed25519"

	"gorm.io/gorm"

	"github.com/yu-org/yu/core/context"
)

// Real-fee payment (plan rev. 3, Phase 4): each order's plaintext fee is
// destroyed from the pool at admission and accrued to the block producer
// per (producer, token); the producer later mints a note for the accrued
// amount via ClaimFees.

// FeeCounterScheme accumulates unclaimed fees per (producer pubkey, token).
type FeeCounterScheme struct {
	Producer string `gorm:"primaryKey;column:producer"`
	Token    string `gorm:"primaryKey;column:token"`
	Amount   uint64 `gorm:"column:amount"`
}

func (FeeCounterScheme) TableName() string { return "fee_counters" }

// AccrueFee adds `amount` to the (producer, token) counter, creating the row
// on first use. Uses a checked add so a malicious sequence of orders can
// never overflow the counter (each order's fee is already 64-bit-bounded).
func (ot *OrderBook) AccrueFee(producer, token string, amount uint64) error {
	return ot.db.Transaction(func(tx *gorm.DB) error {
		var row FeeCounterScheme
		err := tx.First(&row, "producer = ? AND token = ?", producer, token).Error
		if err == gorm.ErrRecordNotFound {
			return tx.Create(&FeeCounterScheme{Producer: producer, Token: token, Amount: amount}).Error
		}
		if err != nil {
			return err
		}
		sum := row.Amount + amount
		if sum < row.Amount {
			return fmt.Errorf("fee counter overflow for %s/%s", producer, token)
		}
		return tx.Model(&FeeCounterScheme{}).
			Where("producer = ? AND token = ?", producer, token).
			Update("amount", sum).Error
	})
}

// FeeBalance returns the unclaimed fee for (producer, token).
func (ot *OrderBook) FeeBalance(producer, token string) (uint64, error) {
	var row FeeCounterScheme
	err := ot.db.First(&row, "producer = ? AND token = ?", producer, token).Error
	if err == gorm.ErrRecordNotFound {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return row.Amount, nil
}

// ────────────────────── Writing: ClaimFees ──────────────────────

// ClaimFeesRequest lets the block producer mint one note for exactly its
// accrued fees. `Amount` must equal the current counter; the note commits
// that public amount under the producer's key (proven by claim_fees).
type ClaimFeesRequest struct {
	ProducerPubkey   string  `json:"producer_pubkey"   validate:"required,len=64"`
	Token            TokenID `json:"token"             validate:"required"`
	Amount           uint64  `json:"amount"`
	OutputCommitment string  `json:"output_commitment" validate:"required,len=64"`
	Signature        string  `json:"signature"         validate:"required,len=128"`
	ZkProof          string  `json:"zk_proof"          validate:"required"`
}

// claimFeesMessage is the canonical message the producer signs.
func claimFeesMessage(req *ClaimFeesRequest) []byte {
	msg := make([]byte, 0, 160)
	put := func(f []byte) {
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(f)))
		msg = append(msg, l[:]...)
		msg = append(msg, f...)
	}
	put([]byte("invisibook-claim-fees-v1"))
	put([]byte(req.ProducerPubkey))
	put([]byte(req.Token))
	var amt [8]byte
	binary.BigEndian.PutUint64(amt[:], req.Amount)
	put(amt[:])
	put([]byte(req.OutputCommitment))
	return msg
}

// claimFeesBind computes the bind public input (Rust twin:
// note::claim_fees_bind).
func claimFeesBind(chainID uint64, req *ClaimFeesRequest) *big.Int {
	return BindHash(
		[]byte(bindDomain),
		u64be(chainID),
		[]byte("claim_fees"),
		u32be(bindVersion),
		[]byte(req.ProducerPubkey),
		[]byte(req.Token),
		u64be(req.Amount),
		[]byte(req.OutputCommitment),
	)
}

// ClaimFees verifies the producer's signature and the claim_fees proof,
// checks the claimed amount equals the accrued counter, then zeroes the
// counter and appends the minted note to the pool.
func (ot *OrderBook) ClaimFees(ctx *context.WriteContext) error {
	ctx.SetLei(100)

	req := new(ClaimFeesRequest)
	if err := ctx.BindJson(req); err != nil {
		return err
	}
	if err := Validator.Struct(req); err != nil {
		return err
	}

	// Producer signature.
	pubkey, err := hex.DecodeString(req.ProducerPubkey)
	if err != nil || len(pubkey) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid producer pubkey")
	}
	sig, err := hex.DecodeString(req.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("invalid signature encoding")
	}
	if !ed25519.Verify(pubkey, claimFeesMessage(req), sig) {
		return fmt.Errorf("producer signature verification failed")
	}

	// The claimed amount must equal the accrued counter exactly.
	balance, err := ot.FeeBalance(req.ProducerPubkey, string(req.Token))
	if err != nil {
		return err
	}
	if req.Amount != balance {
		return fmt.Errorf("claimed %d != accrued %d", req.Amount, balance)
	}
	if req.Amount == 0 {
		return fmt.Errorf("no accrued fees to claim")
	}

	assetID, err := AssetID(req.Token)
	if err != nil {
		return err
	}
	cmDec, err := HexToDecimal(req.OutputCommitment)
	if err != nil {
		return fmt.Errorf("invalid output_commitment: %w", err)
	}
	bind := claimFeesBind(ot.chainID, req)
	signals := []string{assetID.String(), fmt.Sprintf("%d", req.Amount), cmDec, bind.String()}
	if err := VerifyGroth16(ot.claimFeesVK, req.ZkProof, signals); err != nil {
		return fmt.Errorf("claim_fees proof verification failed: %w", err)
	}

	cm, err := ParseFrHex(req.OutputCommitment)
	if err != nil {
		return fmt.Errorf("output_commitment: %w", err)
	}
	if _, err := ot.Account.ApplyPoolMutation(PoolMutation{
		NoteCms: []*big.Int{cm},
		Height:  uint64(ctx.Block.Height),
		Source:  "claim-fees",
		By:      "claim-fees",
	}); err != nil {
		return fmt.Errorf("minting fee note: %w", err)
	}
	// Zero the counter (a fresh row of Amount=0 is harmless).
	if err := ot.db.Model(&FeeCounterScheme{}).
		Where("producer = ? AND token = ?", req.ProducerPubkey, string(req.Token)).
		Update("amount", 0).Error; err != nil {
		return fmt.Errorf("zeroing fee counter: %w", err)
	}

	ctx.EmitStringEvent("claim-fees: producer=%s token=%s amount=%d",
		req.ProducerPubkey, string(req.Token), req.Amount)
	return nil
}

// ────────────────────── Reading: QueryFees ──────────────────────

// QueryFeesRequest asks for the accrued fee of one (producer, token).
type QueryFeesRequest struct {
	ProducerPubkey string  `json:"producer_pubkey" validate:"required,len=64"`
	Token          TokenID `json:"token"           validate:"required"`
}

// QueryFees returns the accrued unclaimed fee.
func (ot *OrderBook) QueryFees(ctx *context.ReadContext) {
	req := new(QueryFeesRequest)
	if err := ctx.BindJson(req); err != nil {
		ctx.Json(http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if err := Validator.Struct(req); err != nil {
		ctx.Json(http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	amount, err := ot.FeeBalance(req.ProducerPubkey, string(req.Token))
	if err != nil {
		ctx.Json(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	ctx.JsonOk(map[string]uint64{"amount": amount})
}

// sendOrderBind computes the bind public input for a SendOrder v2 request
// (Rust twin: note::send_order_bind).
func sendOrderBind(chainID uint64, req *SendOrderRequest) *big.Int {
	lockToken := req.Subject.Token1
	if req.Type == Buy {
		lockToken = req.Subject.Token2
	}
	return BindHash(
		[]byte(bindDomain),
		u64be(chainID),
		[]byte("send_order"),
		u32be(bindVersion),
		[]byte(req.ID),
		[]byte(lockToken),
		[]byte(req.InputNullifiers[0]),
		[]byte(req.InputNullifiers[1]),
		[]byte(req.Amount),
		[]byte(req.LockedCommitment),
		u64be(req.Fee),
		[]byte(req.ChangeCommitment),
	)
}

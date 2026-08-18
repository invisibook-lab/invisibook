package core

import (
	"crypto/sha256"
	"encoding/hex"
	"math/big"

	"github.com/go-playground/validator/v10"
)

// Validator is the shared validator instance for struct tag validation.
var Validator = validator.New()

// Order is the on-chain domain model of a buy or sell intent.
// `LockedCommitment` is the order's ONLY commitment (locked-only model):
// P2(locked_value, r) over the collateral, which pins the hidden quantity
// through the side-dependent equation needed(q) = q·price + side·(q −
// q·price). `Fee` is the plaintext fee destroyed at admission.
// `IntraBlockIndex` is the transaction index within the block, the 4th
// matching tiebreak.
type Order struct {
	ID               OrderID   `json:"id"      validate:"required"`
	Kind             OrderKind `json:"kind"    validate:"oneof=0 1"`
	Type             TradeType `json:"type"    validate:"oneof=0 1"`
	Subject          TradePair `json:"subject"`
	Price            *big.Int  `json:"price,omitempty"`
	ProtectionPrice  *big.Int  `json:"protection_price,omitempty"`
	ExecutionPrice   *big.Int  `json:"execution_price,omitempty"`
	MatchRound       uint64    `json:"match_round"`
	Pubkey           string    `json:"pubkey"  validate:"required"` // owner's ed25519 pubkey (64-char hex)
	LockedCommitment string    `json:"locked_commitment"`
	Fee              uint64    `json:"fee"`
	BlockHeight      uint32    `json:"block_height"`
	IntraBlockIndex  uint32    `json:"intra_block_index"`
	MatchOrder       OrderID   `json:"match_order,omitempty"`
	Status           OrderStat `json:"status"  validate:"oneof=0 1 2 3 4 5"`
}

// Validate checks all struct tag constraints on the Order.
func (o *Order) Validate() error {
	return Validator.Struct(o)
}

// ComputeOrderID derives a deterministic order ID by SHA-256 hashing the
// concatenation of the input nullifiers. Must match the Rust
// compute_order_id in invisibook-lib.
func ComputeOrderID(inputNullifiers []string) OrderID {
	h := sha256.New()
	for _, nf := range inputNullifiers {
		h.Write([]byte(nf))
	}
	return OrderID(hex.EncodeToString(h.Sum(nil)))
}

// Domain identifier and enum types used across the order modules.
type (
	OrderID   string // hex-encoded SHA-256 of the order's input nullifiers
	OrderKind int    // Limit or Market
	TradeType int    // Buy or Sell
	OrderStat int    // Pending, Matched, Settling, Done, Cancelled, Frozen
)

const (
	Limit OrderKind = iota
	Market
)

const (
	Buy TradeType = iota
	Sell
)

const (
	Pending OrderStat = iota
	Matched
	Done
	Cancelled
	Frozen
	Settling // MPC comparison done, awaiting ZK settlement
)

// TradePair names the two tokens involved in an order. By convention Token1
// is the asset being bought/sold and Token2 is the quote/payment asset.
type TradePair struct {
	Token1 TokenID `json:"token1" validate:"required"`
	Token2 TokenID `json:"token2" validate:"required"`
}

// String renders the pair as "Token1/Token2".
func (tp TradePair) String() string {
	return string(tp.Token1) + "/" + string(tp.Token2)
}

// String returns "BUY", "SELL", or "UNKNOWN" for unexpected values.
func (t TradeType) String() string {
	switch t {
	case Buy:
		return "BUY"
	case Sell:
		return "SELL"
	default:
		return "UNKNOWN"
	}
}

// String returns "LIMIT", "MARKET", or "UNKNOWN".
func (k OrderKind) String() string {
	switch k {
	case Limit:
		return "LIMIT"
	case Market:
		return "MARKET"
	default:
		return "UNKNOWN"
	}
}

// String returns the human-readable name of an OrderStat value.
func (s OrderStat) String() string {
	switch s {
	case Pending:
		return "Pending"
	case Matched:
		return "Matched"
	case Done:
		return "Done"
	case Cancelled:
		return "Cancelled"
	case Frozen:
		return "Frozen"
	case Settling:
		return "Settling"
	default:
		return "Unknown"
	}
}

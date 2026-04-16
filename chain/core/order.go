package core

import (
	"crypto/sha256"
	"encoding/hex"
	"math/big"

	"github.com/go-playground/validator/v10"
	"github.com/iden3/go-iden3-crypto/poseidon"
)

// Validator is the shared validator instance for struct tag validation.
var Validator = validator.New()

type Order struct {
	ID           OrderID    `json:"id"      validate:"required"`
	Type         TradeType  `json:"type"    validate:"oneof=0 1"`
	Subject      TradePair  `json:"subject"`
	Price        *big.Int   `json:"price,omitempty"`
	Amount       CipherText `json:"amount"  validate:"required"`
	Owner        string     `json:"owner"   validate:"required"`
	InputCashIDs []string   `json:"input_cash_ids"`
	MatchOrder   OrderID    `json:"match_order,omitempty"`
	Status       OrderStat  `json:"status"  validate:"oneof=0 1 2 3"`
}

// Validate checks all struct tag constraints on the Order.
func (o *Order) Validate() error {
	return Validator.Struct(o)
}

// bn254r is the BN254 scalar field prime, matching the Rust ark-bn254 Fr modulus.
var bn254r, _ = new(big.Int).SetString(
	"21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)

// strToFieldElem reduces the SHA-256 hash of s into a BN254 scalar field element.
// Must match the Rust side: Fr::from_be_bytes_mod_order(&sha256(s)).
func strToFieldElem(s string) *big.Int {
	h := sha256.Sum256([]byte(s))
	n := new(big.Int).SetBytes(h[:])
	return n.Mod(n, bn254r)
}

// ComputeOrderID derives a deterministic order ID using Poseidon(BN254) over
// five field elements: [type, price, token1, token2, amount].
// String fields are reduced to field elements via SHA-256 mod BN254r.
// Must match the Rust compute_order_id in invisibook-lib.
func ComputeOrderID(orderType TradeType, subject TradePair, price *big.Int, amount CipherText) OrderID {
	typeElem := big.NewInt(int64(orderType))

	priceElem := big.NewInt(0)
	if price != nil {
		priceElem = new(big.Int).Set(price)
	}

	token1Elem := strToFieldElem(string(subject.Token1))
	token2Elem := strToFieldElem(string(subject.Token2))
	amountElem := strToFieldElem(string(amount))

	result, err := poseidon.Hash([]*big.Int{typeElem, priceElem, token1Elem, token2Elem, amountElem})
	if err != nil {
		panic("ComputeOrderID: poseidon hash failed: " + err.Error())
	}

	// Pad to 32 bytes big-endian to match Rust's into_bigint().to_bytes_be().
	b := result.Bytes()
	padded := make([]byte, 32)
	copy(padded[32-len(b):], b)
	return OrderID(hex.EncodeToString(padded))
}

type (
	OrderID    string
	TradeType  int
	CipherText string
	OrderStat  int
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
)

type TradePair struct {
	Token1 TokenID `json:"token1" validate:"required"`
	Token2 TokenID `json:"token2" validate:"required"`
}

func (tp TradePair) String() string {
	return string(tp.Token1) + "/" + string(tp.Token2)
}

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
	default:
		return "Unknown"
	}
}

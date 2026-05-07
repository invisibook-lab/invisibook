package core

import "math/big"

// TokenID is the global unique name of a UDT (User-Defined Token).
type TokenID string

// IsNative reports whether this token id is the chain's native token.
func (tid TokenID) IsNative() bool {
	return tid == NativeToken.Name
}

// UDT is a User-Defined Token registered on this chain. Tokens originating from
// another chain set OriginalToken to point back at the source contract.
type UDT struct {
	Name          TokenID     `json:"name"`    // global unique name
	Creator       string      `json:"creator"` // Creator of the UDT, it is Script ID
	Description   string      `json:"description"`
	OriginalToken *ChainToken `json:"original_token,omitempty"`
	Total         *big.Int    `json:"total"`
	Locked        *big.Int    `json:"locked"`
	Issued        *big.Int    `json:"issued"`
}

// IsNative reports whether this UDT is the chain's native token.
func (u *UDT) IsNative() bool {
	return u.Name == NativeToken.Name
}

// ChainToken locates a token contract on a foreign chain that backs a UDT
// minted on Invisibook through the bridge.
type ChainToken struct {
	ChainURL     string `json:"chain_url"`
	TokenAddress []byte `json:"token_address"`
}

// NativeToken is the singleton UDT for the chain's native asset "invis".
var NativeToken = UDT{
	Name:          "invis",
	Description:   "Invisble Chain Native Token",
	OriginalToken: nil,
	Total:         new(big.Int).SetUint64(1000000000000000000),
	Locked:        new(big.Int).SetUint64(0),
	Issued:        new(big.Int).SetUint64(1000000000000000),
}

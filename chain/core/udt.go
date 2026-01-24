package core

import "math/big"

type TokenID string

func (tid TokenID) IsNative() bool {
	return tid == NativeToken.Name
}

type UDT struct {
	Name          TokenID     `json:"name"`    // global unique name
	Creator       string      `json:"creator"` // Creator of the UDT, it is Script ID
	Description   string      `json:"description"`
	OriginalToken *ChainToken `json:"original_token,omitempty"`
	Total         *big.Int    `json:"total"`
	Locked        *big.Int    `json:"locked"`
	Issued        *big.Int    `json:"issued"`
}

func (u *UDT) IsNative() bool {
	return u.Name == NativeToken.Name
}

type ChainToken struct {
	ChainURL     string `json:"chain_url"`
	TokenAddress []byte `json:"token_address"`
}

var NativeToken = UDT{
	Name:          "invis",
	Description:   "Invisble Chain Native Token",
	OriginalToken: nil,
	Total:         new(big.Int).SetUint64(1000000000000000000),
	Locked:        new(big.Int).SetUint64(0),
	Issued:        new(big.Int).SetUint64(1000000000000000),
}

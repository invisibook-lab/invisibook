package core

import (
	"encoding/binary"
	"strconv"
)

// SendOrderSigningDomain domain-separates the SendOrder signing message from
// every other ed25519 message in the system (e.g. the co-zk settle messages).
const SendOrderSigningDomain = "invisibook-send-order-v1"

// appendSigningField appends `s` to `buf` prefixed with its u32 big-endian
// byte length, so consecutive fields of arbitrary content concatenate
// without ambiguity.
func appendSigningField(buf []byte, s string) []byte {
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(s)))
	buf = append(buf, l[:]...)
	return append(buf, s...)
}

// appendSigningList appends a u32 big-endian element count followed by each
// element as a length-prefixed field, so list boundaries are unambiguous.
func appendSigningList(buf []byte, list []string) []byte {
	var c [4]byte
	binary.BigEndian.PutUint32(c[:], uint32(len(list)))
	buf = append(buf, c[:]...)
	for _, s := range list {
		buf = appendSigningField(buf, s)
	}
	return buf
}

// SendOrderSigningMessage builds the canonical byte string the order owner
// must ed25519-sign to authorize a SendOrder request. It covers every request
// field except the signature itself and the zk proof (the proof is already
// bound to its commitments through public-input verification), so no observer
// can alter price, pair, amount, fees, or change destination between signing
// and on-chain inclusion. Must stay in lockstep with Rust
// `send_order_signing_message` in invisibook-lib.
func SendOrderSigningMessage(req *SendOrderRequest) []byte {
	priceStr := ""
	if req.Price != nil {
		priceStr = req.Price.String()
	}
	changeFlag := "0"
	changeCashID := ""
	changeAmount := ""
	if req.Change != nil {
		changeFlag = "1"
		changeCashID = req.Change.CashID
		changeAmount = string(req.Change.Amount)
	}

	buf := make([]byte, 0, 256)
	buf = appendSigningField(buf, SendOrderSigningDomain)
	buf = appendSigningField(buf, string(req.ID))
	buf = appendSigningField(buf, strconv.Itoa(int(req.Type)))
	buf = appendSigningField(buf, string(req.Subject.Token1))
	buf = appendSigningField(buf, string(req.Subject.Token2))
	buf = appendSigningField(buf, priceStr)
	buf = appendSigningField(buf, string(req.Amount))
	buf = appendSigningField(buf, req.Pubkey)
	buf = appendSigningList(buf, req.InputCashIDs)
	buf = appendSigningList(buf, req.HandlingFee)
	buf = appendSigningField(buf, changeFlag)
	buf = appendSigningField(buf, changeCashID)
	buf = appendSigningField(buf, changeAmount)
	buf = appendSigningField(buf, string(req.LockedCommitment))
	return buf
}

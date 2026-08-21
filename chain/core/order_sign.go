package core

import (
	"encoding/binary"
	"strconv"
)

// SendOrderSigningDomain domain-separates the SendOrder v2 signing message
// from every other ed25519 message in the system.
const SendOrderSigningDomain = "invisibook-send-order-v2"

// appendSigningField appends `s` to `buf` prefixed with its u32 big-endian
// byte length, so consecutive fields of arbitrary content concatenate
// without ambiguity.
func appendSigningField(buf []byte, s string) []byte {
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(s)))
	buf = append(buf, l[:]...)
	return append(buf, s...)
}

// SendOrderSigningMessage builds the canonical byte string the order owner
// ed25519-signs to authorize a SendOrder v2 request. It covers every field
// except the signature and the zk proof (the proof is already bound to its
// commitments and to these fields via `bind`). Must stay in lockstep with
// Rust `send_order_signing_message` in invisibook-lib.
func SendOrderSigningMessage(req *SendOrderRequest) []byte {
	priceStr := ""
	if req.Price != nil {
		priceStr = req.Price.String()
	}
	var feeBytes [8]byte
	binary.BigEndian.PutUint64(feeBytes[:], req.Fee)

	buf := make([]byte, 0, 256)
	buf = appendSigningField(buf, SendOrderSigningDomain)
	buf = appendSigningField(buf, string(req.ID))
	buf = appendSigningField(buf, strconv.Itoa(int(req.Type)))
	buf = appendSigningField(buf, string(req.Subject.Token1))
	buf = appendSigningField(buf, string(req.Subject.Token2))
	buf = appendSigningField(buf, priceStr)
	buf = appendSigningField(buf, req.Pubkey)
	buf = appendSigningField(buf, req.Anchor)
	buf = appendSigningField(buf, req.InputNullifiers[0])
	buf = appendSigningField(buf, req.InputNullifiers[1])
	buf = appendSigningField(buf, req.LockedCommitment)
	buf = appendSigningField(buf, string(feeBytes[:]))
	buf = appendSigningField(buf, req.ChangeCommitment)
	return buf
}

package consensus

import (
	"errors"
	"fmt"

	"github.com/golang/protobuf/proto"
	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/yu-org/yu/core/types"
	"github.com/yu-org/yu/core/types/goproto"
)

// MaxHeaderLen caps the encoded header a submit cell may carry. It must match
// MAX_HEADER_LEN in ckb/contracts/pob-submission, which refuses anything
// longer on chain (R5.1).
//
// A PoB header is well under a kilobyte; the cap exists so that a submit cell
// cannot be used to park arbitrary amounts of data on L1, not because honest
// headers come anywhere near it.
const MaxHeaderLen = 4096

// ErrHeaderTooLarge reports a header whose encoding exceeds MaxHeaderLen.
var ErrHeaderTooLarge = errors.New("encoded header exceeds the submit cell limit")

// EncodeHeader returns the bytes a submit cell carries for `header`: the
// header in yu's own protobuf encoding, unchanged.
//
// The whole header goes to L1, Extra included. That is what lets L1 stand on
// its own as a record of the chain: height, parent link, producer, VRF output
// and payment are all readable straight off the cell, which is what fork
// choice decides on (decideBatch).
//
// `header` must not be nil.
func EncodeHeader(header *types.Header) ([]byte, error) {
	if header == nil {
		return nil, errors.New("no header to encode")
	}
	raw, err := proto.Marshal(header.ToPb())
	if err != nil {
		return nil, fmt.Errorf("encoding header at height %d: %w", header.Height, err)
	}
	if len(raw) > MaxHeaderLen {
		return nil, fmt.Errorf("%w: height %d encodes to %d bytes, limit %d",
			ErrHeaderTooLarge, header.Height, len(raw), MaxHeaderLen)
	}
	return raw, nil
}

// DecodeAnchoredHeader decodes the header a submit cell carries.
//
// Decoding says nothing about whether the header is genuine: anyone may write
// a submit cell. VerifyHeaderSeal is what establishes that its hash is the one
// its contents produce and that its producer signed it.
//
// `raw` is untrusted L1 data: anything malformed is an error, never a panic.
func DecodeAnchoredHeader(raw []byte) (*types.Header, error) {
	if len(raw) == 0 {
		return nil, errors.New("submit cell carries no header")
	}
	var pb goproto.Header
	if err := proto.Unmarshal(raw, &pb); err != nil {
		return nil, fmt.Errorf("decoding anchored header: %w", err)
	}
	// HeaderFromPb panics on a peer ID it cannot parse, and this data comes
	// from whoever paid for the cell. Checked here so that a bad cell is
	// skipped instead of taking the node down.
	if pb.PeerId != "" {
		if _, err := peer.Decode(pb.PeerId); err != nil {
			return nil, fmt.Errorf("anchored header carries a malformed peer ID: %w", err)
		}
	}
	return types.HeaderFromPb(&pb), nil
}

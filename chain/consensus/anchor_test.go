package consensus

import (
	"bytes"
	"errors"
	"testing"

	"github.com/golang/protobuf/proto"

	"github.com/yu-org/yu/core/types"
	"github.com/yu-org/yu/core/types/goproto"
)

// What goes to L1 has to come back as the same header: decoding the cell
// must yield one whose seal still verifies, or no node could choose it.
func TestAnchoredHeaderRoundTrips(t *testing.T) {
	block, _, _, _ := sealedRival(t, &MockL1PaymentVerifier{})

	raw, err := EncodeHeader(block.Header)
	if err != nil {
		t.Fatalf("EncodeHeader: %v", err)
	}
	got, err := DecodeAnchoredHeader(raw)
	if err != nil {
		t.Fatalf("DecodeAnchoredHeader: %v", err)
	}
	if got.Hash != block.Hash {
		t.Fatalf("decoded header names %s, want %s", got.Hash, block.Hash)
	}
	if err := VerifyHeaderSeal(got); err != nil {
		t.Fatalf("decoded header no longer verifies: %v", err)
	}
}

// Anyone can write a submit cell, so garbage must come back as an error. The
// peer ID case matters most: yu's decoder panics on it.
func TestDecodeAnchoredHeaderRejectsMalformedData(t *testing.T) {
	badPeer, err := proto.Marshal(&goproto.Header{Height: 1, PeerId: "not-a-peer-id"})
	if err != nil {
		t.Fatalf("encoding the test header: %v", err)
	}
	cases := map[string][]byte{
		"empty":        nil,
		"not protobuf": {0xff, 0xff, 0xff},
		"bad peer id":  badPeer,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeAnchoredHeader(raw); err == nil {
				t.Fatal("malformed submit cell data was accepted")
			}
		})
	}
}

// The cap matches the on-chain limit, so a header over it is refused here
// rather than by the script after paying for the round trip.
func TestEncodeHeaderRejectsAnOversizedHeader(t *testing.T) {
	header := &types.Header{Height: 1, Extra: bytes.Repeat([]byte{1}, MaxHeaderLen)}

	if _, err := EncodeHeader(header); !errors.Is(err, ErrHeaderTooLarge) {
		t.Fatalf("expected ErrHeaderTooLarge, got %v", err)
	}
}

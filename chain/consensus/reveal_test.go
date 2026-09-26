package consensus

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/yu-org/yu/common"
	"github.com/yu-org/yu/core/types"
)

// sampleBlockReveal is one well-formed reveal message.
func sampleBlockReveal() *BlockReveal {
	return &BlockReveal{
		L2BlockHeight: 12,
		L2BlockHash:   "0xblock",
		Random:        strings.Repeat("ab", 32),
		L1BlockHash:   "0xl1block",
		TxIdx:         4,
		MinerPubkey:   "0xminer",
	}
}

func TestRevealEncodeDecodeRoundTrip(t *testing.T) {
	want := sampleBlockReveal()

	raw, err := EncodeReveal(want)
	if err != nil {
		t.Fatalf("EncodeReveal: %v", err)
	}
	got, err := DecodeReveal(raw)
	if err != nil {
		t.Fatalf("DecodeReveal: %v", err)
	}

	if *got != *want {
		t.Fatalf("round trip = %+v, want %+v", got, want)
	}
}

// Every field is load-bearing, so a message missing one is refused at the door
// rather than stored and tripped over later during fork choice.
func TestDecodeRevealRejectsMalformedMessages(t *testing.T) {
	cases := []struct {
		name  string
		spoil func(*BlockReveal)
	}{
		{"no block hash", func(r *BlockReveal) { r.L2BlockHash = "" }},
		{"short random", func(r *BlockReveal) { r.Random = "abcd" }},
		{"no random", func(r *BlockReveal) { r.Random = "" }},
		{"no L1 block", func(r *BlockReveal) { r.L1BlockHash = "" }},
		{"no producer", func(r *BlockReveal) { r.MinerPubkey = "" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reveal := sampleBlockReveal()
			tc.spoil(reveal)

			raw, err := EncodeReveal(reveal)
			if err != nil {
				t.Fatalf("EncodeReveal: %v", err)
			}
			if _, err := DecodeReveal(raw); err == nil {
				t.Fatal("expected the reveal to be refused, got none")
			}
		})
	}
}

func TestDecodeRevealRejectsGarbage(t *testing.T) {
	if _, err := DecodeReveal([]byte("not json")); err == nil {
		t.Fatal("garbage must not decode into a reveal")
	}
}

// The store row and the wire message carry the same facts, and a node answers
// a catching-up peer by turning rows back into messages — so the conversion
// has to survive both directions unchanged.
func TestRevealRowRoundTrip(t *testing.T) {
	want := sampleBlockReveal()

	got := RevealFromRow(want.ToRow())

	if *got != *want {
		t.Fatalf("row round trip = %+v, want %+v", got, want)
	}
}

// blockBy builds a block produced by `producer`.
func blockBy(producer []byte) *types.Block {
	return &types.Block{Header: &types.Header{
		Height:      9,
		Hash:        common.HexToHash("0xfeed"),
		MinerPubkey: producer,
	}}
}

// The producer and the submitter are not the same person. Anchoring a
// commitment on L1 takes no identity at all, and this node submits one for
// every block it adopts from someone else — so a reveal has to name the miner
// that produced the block, never the node that submitted it. Naming the
// submitter would relabel another miner's block as ours, and the VRF and
// payment checks that read this field would all be aimed at the wrong key.
func TestNewBlockRevealNamesTheProducerNotTheSubmitter(t *testing.T) {
	producer := []byte{0xde, 0xad, 0xbe, 0xef}

	got := newBlockReveal(blockBy(producer), strings.Repeat("ab", 32), &L1Location{
		BlockHash: "0xl1",
		TxIdx:     3,
	})

	if got.MinerPubkey != hex.EncodeToString(producer) {
		t.Fatalf("MinerPubkey = %q, want the block's producer %q",
			got.MinerPubkey, hex.EncodeToString(producer))
	}
}

// The rest of the message has to survive the mapping too: an opening that
// points at the wrong block or the wrong L1 transaction opens nothing.
func TestNewBlockRevealCarriesBlockAndLocation(t *testing.T) {
	block := blockBy([]byte{0x01})
	loc := &L1Location{BlockHash: "0xl1", TxIdx: 3}
	random := strings.Repeat("cd", 32)

	got := newBlockReveal(block, random, loc)

	if got.L2BlockHeight != block.Height {
		t.Fatalf("height = %d, want %d", got.L2BlockHeight, block.Height)
	}
	if got.L2BlockHash != block.Hash.String() {
		t.Fatalf("block hash = %q, want %q", got.L2BlockHash, block.Hash.String())
	}
	if got.Random != random {
		t.Fatalf("random = %q, want %q", got.Random, random)
	}
	if got.L1BlockHash != loc.BlockHash || got.TxIdx != loc.TxIdx {
		t.Fatalf("location = (%q, %d), want (%q, %d)",
			got.L1BlockHash, got.TxIdx, loc.BlockHash, loc.TxIdx)
	}
	// What this builds must clear the same bar a peer's reveal has to.
	if err := got.Validate(); err != nil {
		t.Fatalf("a freshly built reveal must validate, got %v", err)
	}
}

package consensus

import (
	"testing"

	"github.com/yu-org/yu/common"
)

// The one thing the genesis hash may never be. yu's own attempt at it —
// HexToHash("genesis") — yields all zeroes, and since the genesis block's
// PrevHash is zero too, that records the block as its own parent: a walk of
// the block tree from the last finalized block then never terminates.
func TestGenesisHashIsNotZero(t *testing.T) {
	for _, chainID := range []uint64{0, 1, 1926} {
		if got := GenesisHash(chainID); got == (common.Hash{}) {
			t.Fatalf("GenesisHash(%d) is the zero hash", chainID)
		}
	}
	// The value yu tried to use, so that a regression back to it is loud.
	if common.HexToHash("genesis") != (common.Hash{}) {
		t.Skip("HexToHash no longer collapses a non-hex string to zero; revisit defineGenesis")
	}
}

// Two chains must not share a genesis, or blocks from one would link cleanly
// onto the other.
func TestGenesisHashSeparatesChains(t *testing.T) {
	if GenesisHash(1) == GenesisHash(2) {
		t.Fatal("two chain ids produce the same genesis hash")
	}
}

// It is derived from the chain id alone, never from the block the kernel
// hands over: that one carries the local peer id and the moment this node
// booted, so hashing it would give every node its own genesis.
func TestGenesisHashIsStable(t *testing.T) {
	first := GenesisHash(1926)
	for i := 0; i < 3; i++ {
		if GenesisHash(1926) != first {
			t.Fatal("GenesisHash is not deterministic")
		}
	}
}

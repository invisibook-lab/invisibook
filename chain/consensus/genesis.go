package consensus

import (
	"encoding/binary"

	"github.com/sirupsen/logrus"

	"github.com/yu-org/yu/common"
	"github.com/yu-org/yu/core/types"
)

// genesisDomain separates this chain's genesis hash from any other value that
// might be hashed the same way. It is part of the chain's identity: change it
// and every node computes a different genesis, which is a different chain.
const genesisDomain = "invisibook/genesis/v1"

// GenesisHash returns the hash the genesis block of chain `chainID` must
// have.
//
// It is derived rather than computed over the block, because the block's own
// header is not the same on two nodes: the kernel stamps it with the local
// peer ID and the moment that node happened to boot. Hashing that would give
// every node its own genesis, and since block 1 links back to it by hash, two
// nodes would build chains that can never agree on anything.
//
// What it must not be is the zero hash. yu means to give genesis a
// distinctive one — `defineGenesis` in its synchronizer sets
// `HexToHash("genesis")` — but "genesis" is not hex, so that call yields all
// zeroes. The genesis block's `PrevHash` is all zeroes too, never having been
// set, which leaves the block recorded as its own parent: a lookup of "the
// blocks whose parent is the zero hash" returns genesis itself. Walking the
// block tree from there never terminates, and since the last finalized block
// is genesis until something finalizes, that walk is on the path of every
// attempt to finalize anything.
func GenesisHash(chainID uint64) common.Hash {
	raw := make([]byte, 0, len(genesisDomain)+8)
	raw = append(raw, genesisDomain...)
	raw = binary.BigEndian.AppendUint64(raw, chainID)
	return common.BytesToHash(common.Sha256(raw))
}

// defineGenesis gives the genesis block the identity yu left it without, and
// writes it down.
//
// It runs from InitChain, which the kernel calls on every tripod in
// registration order with the one genesis block. The synchronizer is
// registered first and has already stored its version by the time this runs,
// so this is a correction rather than a first write — and it has to be, since
// the synchronizer overwrites the hash unconditionally and would undo
// anything done earlier.
//
// The header is normalised along with the hash. The timestamp and peer ID the
// kernel stamps on genesis say which node booted first and nothing else; a
// chain's first block should read the same on every node that carries it.
// It returns this node's own copy of the block it stored. A copy because the
// kernel hands the same block to every tripod, and the synchronizer's turn
// comes after this one: it writes its zero hash straight over the shared
// header, so anything kept by reference here would be that zero hash by the
// time it was read.
func (p *ProofOfBuy) defineGenesis(genesis *types.Block) *types.Block {
	if genesis == nil || genesis.Header == nil {
		logrus.Error("PoB: the kernel passed no genesis block; the chain cannot be initialised")
		return nil
	}

	want := GenesisHash(genesis.ChainID)
	genesis.Hash = want
	genesis.PrevHash = common.Hash{}
	genesis.Timestamp = 0
	genesis.PeerID = ""

	// Insert-if-absent, and this tripod is registered ahead of the
	// synchronizer precisely so that it is the one to get there first. The
	// row cannot be corrected afterwards: the chain offers to rewrite a block
	// by height or by hash, and at height zero the first filter is a zero
	// value the query builder drops, while the second needs the hash that is
	// the very thing being changed.
	if err := p.Chain.SetGenesis(genesis); err != nil {
		logrus.Errorf("PoB: writing the genesis block: %v", err)
		return nil
	}

	stored, err := p.Chain.GetGenesis()
	if err != nil {
		logrus.Errorf("PoB: reading back the genesis block: %v", err)
		return nil
	}
	if stored == nil || stored.Header == nil || stored.Hash != want {
		// Somebody else's genesis is already on disk. Every block links back
		// to it by hash, so the chain cannot be run against a different one.
		logrus.Fatalf("PoB: the stored genesis block has hash %s, want %s; "+
			"this database belongs to another chain", storedHash(stored), want.String())
		return nil
	}

	header := *genesis.Header
	mine := &types.Block{Header: &header}

	p.finalizeGenesis(mine)
	logrus.Infof("PoB: genesis block defined, hash=%s chain_id=%d", want.String(), genesis.ChainID)
	return mine
}

// storedHash renders a stored block's hash for a message, tolerating the
// block being absent.
func storedHash(block *types.Block) string {
	if block == nil || block.Header == nil {
		return "<none>"
	}
	return block.Hash.String()
}

// finalizeGenesis records the genesis block as finalized, which is also what
// puts it in the chain's cache of the last finalized block.
func (p *ProofOfBuy) finalizeGenesis(genesis *types.Block) {
	if err := p.Chain.Finalize(genesis); err != nil {
		logrus.Errorf("PoB: finalizing the genesis block: %v", err)
	}
}

// restoreFinalizedGenesis puts the chain's cache of the last finalized block
// back to the genesis block this node actually stored.
//
// The synchronizer runs its own defineGenesis after this tripod's, and while
// its write to the block table is refused — the row is already there — its
// Finalize call still caches the zero-hash block it built. Every walk of the
// block tree starts from whatever that cache holds, and a hash no block links
// back to yields no candidate branches at all, so nothing would ever settle.
//
// Only the cache is at stake, and only until something above genesis is
// finalized, after which this stops matching and does nothing.
func (p *ProofOfBuy) restoreFinalizedGenesis(genesis *types.Block) {
	if genesis == nil {
		return
	}
	last, err := p.Chain.LastFinalizedCompact()
	if err != nil {
		logrus.Errorf("PoB: reading the last finalized block: %v", err)
		return
	}
	if last == nil || last.Header == nil || last.Hash != (common.Hash{}) {
		return
	}
	logrus.Warn("PoB: the last finalized block was cached with a zero hash; restoring genesis")
	p.finalizeGenesis(genesis)
}

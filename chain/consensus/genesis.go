package consensus

import (
	"encoding/binary"

	"github.com/sirupsen/logrus"
	"github.com/yu-org/yu/common"
	"github.com/yu-org/yu/core/types"
)

// DefineGenesis builds this chain's genesis block: an empty block at height
// zero, carrying the chain ID and the L1 height n it corresponds to
// (anchor_genesis_l1_height).
//
// The kernel calls it once, before any InitChain, and only when the database
// holds no genesis yet; it then writes the block as finalized. Being empty
// and derived from those two values alone, it is the same block on every
// node.
func (p *ProofOfBuy) DefineGenesis() *types.Block {
	genesis, err := p.genesisBlock()
	if err != nil {
		// Returning nil makes the kernel refuse to start, which is what a
		// chain with no genesis has to do.
		logrus.Errorf("PoB: building the genesis block: %v", err)
		return nil
	}
	logrus.Infof("PoB: genesis block defined, hash=%s chain_id=%d", genesis.Hash.String(), genesis.ChainID)
	return genesis
}

// genesisBlock builds the genesis block of the chain this node is configured
// for. Its hash is computed the way yu hashes any block, the Sha256 of the
// encoded block; since the block holds only the chain ID and n, every node of
// one chain arrives at the same hash, and two chains never share one.
//
// n is in the genesis block, not merely in each node's config, because every
// node must use the same n or they read different L1 windows and decide
// different chains. Written into the header, a different n is a different
// genesis hash: checkGenesis refuses a database built with another one, and
// block 1 links to nothing on a node configured with the wrong value.
func (p *ProofOfBuy) genesisBlock() (*types.Block, error) {
	genesis := p.Chain.NewEmptyBlock()
	genesis.Height = 0
	genesis.Extra = encodeGenesisL1Height(p.cfg.AnchorGenesisL1Height)
	encoded, err := genesis.Encode()
	if err != nil {
		return nil, err
	}
	genesis.Hash = common.BytesToHash(common.Sha256(encoded))
	return genesis, nil
}

// checkGenesis stops the node when the stored genesis is not the one
// DefineGenesis builds. The kernel only defines a genesis for an empty
// database, so a mismatch means the database belongs to another chain — or
// to another definition of this one — and every block in it links back to a
// genesis this node would not produce.
func (p *ProofOfBuy) checkGenesis() {
	stored, err := p.Chain.GetGenesis()
	if err != nil {
		logrus.Fatalf("PoB: reading the genesis block: %v", err)
	}
	want, err := p.genesisBlock()
	if err != nil {
		logrus.Fatalf("PoB: building the genesis block to check against: %v", err)
	}
	if stored.Hash != want.Hash {
		logrus.Fatalf("PoB: the stored genesis block has hash %s, want %s; "+
			"this database belongs to another chain", stored.Hash.String(), want.Hash.String())
	}
}

// encodeGenesisL1Height renders n as the genesis header's Extra: 8 bytes,
// big-endian. Genesis carries no consensus data, so Extra is free for it.
func encodeGenesisL1Height(n uint64) []byte {
	out := make([]byte, 8)
	binary.BigEndian.PutUint64(out, n)
	return out
}

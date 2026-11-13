package consensus

import (
	"encoding/binary"
	"github.com/invisibook-lab/invisibook/account"
	"github.com/yu-org/yu/core/state/sqlstate"
	"github.com/yu-org/yu/core/tripod"

	"github.com/sirupsen/logrus"
	"github.com/yu-org/yu/common"
	"github.com/yu-org/yu/core/types"
)

// Genesis owns chain identity and initial state independently of the consensus engine.
type Genesis struct {
	*tripod.Tripod
	cfg         *Config
	engine      string
	GenesisRoot common.Hash
	state       *sqlstate.State
	cash        *sqlstate.Table
	accountCfg  *account.Config
}

// NewGenesis computes the initial commitment; state and cash must use registered business schemas.
func NewGenesis(engine string, cfg *Config, state *sqlstate.State, cash *sqlstate.Table, accountCfg *account.Config) (*Genesis, error) {
	root, err := genesisStateRoot(accountCfg)
	if err != nil {
		return nil, err
	}
	return &Genesis{Tripod: tripod.NewTripodWithName("genesis"), cfg: cfg, engine: engine, GenesisRoot: root, state: state, cash: cash, accountCfg: accountCfg}, nil
}

// InitChain refuses a database belonging to another chain or consensus selection.
func (p *Genesis) InitChain() { p.checkGenesis() }

// DefineGenesis builds this chain's genesis block: an empty block at height
// zero, committing to the selected consensus engine and initial state. PoB
// also binds the L1 height n (anchor_genesis_l1_height).
//
// The kernel calls it once, before any InitChain, and only when the database
// holds no genesis yet; it then writes the block as finalized. Being empty
// and derived from shared chain parameters, it is the same block on every
// node.
func (p *Genesis) DefineGenesis() *types.Block {
	genesis, err := p.genesisBlock()
	if err != nil {
		// Returning nil makes the kernel refuse to start, which is what a
		// chain with no genesis has to do.
		logrus.Errorf("PoB: building the genesis block: %v", err)
		return nil
	}
	if p.state != nil {
		if err := p.initializeState(genesis); err != nil {
			logrus.Fatalf("initializing genesis state: %v", err)
		}
	}
	logrus.Infof("PoB: genesis block defined, hash=%s chain_id=%d", genesis.Hash.String(), genesis.ChainID)
	return genesis
}

// genesisBlock builds the genesis block of the chain this node is configured
// for. Its hash is computed the way yu hashes any block, the Sha256 of the
// encoded block; since the block holds the chain ID, engine and initial root, every node of
// one chain arrives at the same hash, and two chains never share one.
//
// n is in the genesis block, not merely in each node's config, because every
// node must use the same n or they read different L1 windows and decide
// different chains. Written into the header, a different n is a different
// genesis hash: checkGenesis refuses a database built with another one, and
// block 1 links to nothing on a node configured with the wrong value.
func (p *Genesis) genesisBlock() (*types.Block, error) {
	genesis := p.Chain.NewEmptyBlock()
	genesis.Height = 0
	genesis.StateRoot = p.GenesisRoot
	n := uint64(0)
	if p.engine == "pob" {
		n = p.cfg.AnchorGenesisL1Height
	}
	genesis.Extra = append(encodeGenesisL1Height(n), []byte(p.engine)...)
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
func (p *Genesis) checkGenesis() {
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

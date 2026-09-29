package consensus

import (
	"path/filepath"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/yu-org/yu/common"
	"github.com/yu-org/yu/config"
	"github.com/yu-org/yu/core/blockchain"
	"github.com/yu-org/yu/core/env"
	"github.com/yu-org/yu/core/tripod"
	"github.com/yu-org/yu/core/types"
)

// noTxDB is a transaction store holding nothing; a genesis block has no
// transactions.
type noTxDB struct{}

func (noTxDB) GetTxn(common.Hash) (*types.SignedTxn, error)        { return nil, nil }
func (noTxDB) GetTxns([]common.Hash) ([]*types.SignedTxn, error)   { return nil, nil }
func (noTxDB) ExistTxn(common.Hash) bool                           { return false }
func (noTxDB) SetTxns([]*types.SignedTxn) error                    { return nil }
func (noTxDB) SetReceipts(map[common.Hash]*types.Receipt) error    { return nil }
func (noTxDB) GetReceipt(common.Hash) (*types.Receipt, error)      { return nil, nil }
func (noTxDB) GetReceipts([]common.Hash) ([]*types.Receipt, error) { return nil, nil }
func (noTxDB) SetReceipt(common.Hash, *types.Receipt) error        { return nil }

// newGenesisPoB returns a ProofOfBuy on a fresh yu chain of `chainID`, with
// nothing but the chain wired in.
func newGenesisPoB(t *testing.T, chainID uint64) (*ProofOfBuy, *blockchain.BlockChain) {
	t.Helper()
	return openGenesisPoB(chainID, filepath.Join(t.TempDir(), "chain.db"))
}

// openGenesisPoB is newGenesisPoB on the database at `dsn`, which may already
// hold a chain.
func openGenesisPoB(chainID uint64, dsn string) (*ProofOfBuy, *blockchain.BlockChain) {
	cfg := config.InitDefaultCfg()
	cfg.BlockChain.ChainID = chainID
	cfg.BlockChain.ChainDB.Dsn = dsn
	chain := blockchain.NewBlockChain(common.FullNode, &cfg.BlockChain, noTxDB{})

	p := &ProofOfBuy{Tripod: tripod.NewTripod()}
	p.SetChainEnv(&env.ChainEnv{Chain: chain})
	return p, chain
}

// DefineGenesis must yield a block the kernel accepts: height zero, a hash
// that is not the NullHash, and the configured chain ID.
func TestDefineGenesis(t *testing.T) {
	p, chain := newGenesisPoB(t, 1926)
	genesis := p.DefineGenesis()

	if genesis.Height != 0 || genesis.ChainID != 1926 {
		t.Fatalf("height=%d chain_id=%d, want 0 and 1926", genesis.Height, genesis.ChainID)
	}
	// Hashed the way yu hashes any block: the Sha256 of the encoded block.
	unhashed := *genesis.Header
	unhashed.Hash = common.Hash{}
	encoded, err := (&types.Block{Header: &unhashed}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	if want := common.BytesToHash(common.Sha256(encoded)); genesis.Hash != want || genesis.Hash == (common.Hash{}) {
		t.Fatalf("hash = %s, want %s", genesis.Hash.String(), want.String())
	}
	// What the kernel does with it.
	if err := chain.SetGenesis(genesis); err != nil {
		t.Fatalf("the kernel would reject this genesis: %v", err)
	}
	finalized, err := chain.LastFinalizedCompact()
	if err != nil || finalized.Hash != genesis.Hash {
		t.Fatalf("last finalized = %v, %v; want the genesis", finalized, err)
	}
	p.checkGenesis()
}

// Every node of a chain must define the same genesis, or block 1 would link
// to a different parent on each.
func TestDefineGenesisIsTheSameOnEveryNode(t *testing.T) {
	a, _ := newGenesisPoB(t, 7)
	b, _ := newGenesisPoB(t, 7)
	if a.DefineGenesis().Hash != b.DefineGenesis().Hash {
		t.Fatal("two nodes of one chain define different genesis blocks")
	}
	c, _ := newGenesisPoB(t, 8)
	if a.DefineGenesis().Hash == c.DefineGenesis().Hash {
		t.Fatal("two chains share a genesis hash")
	}
}

// A database written by another chain must stop the node rather than be
// built on.
func TestCheckGenesisRefusesAnotherChain(t *testing.T) {
	dsn := filepath.Join(t.TempDir(), "chain.db")
	other, chain := openGenesisPoB(1, dsn)
	if err := chain.SetGenesis(other.DefineGenesis()); err != nil {
		t.Fatal(err)
	}

	// logrus.Fatal would end the test binary; turn the exit into a panic.
	logger := logrus.StandardLogger()
	prev := logger.ExitFunc
	logger.ExitFunc = func(int) { panic("exit") }
	defer func() { logger.ExitFunc = prev }()

	// A node configured for chain 2, pointed at chain 1's database.
	mine, _ := openGenesisPoB(2, dsn)
	exited := func() (exited bool) {
		defer func() { exited = recover() != nil }()
		mine.checkGenesis()
		return false
	}()
	if !exited {
		t.Fatal("checkGenesis accepted another chain's genesis")
	}
}

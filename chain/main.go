package main

import (
	"flag"
	"log"

	"github.com/sirupsen/logrus"
	"github.com/yu-org/yu/apps/synchronizer"
	"github.com/yu-org/yu/core/keypair"
	"github.com/yu-org/yu/core/startup"

	"github.com/invisibook-lab/invisibook/account"
	"github.com/invisibook-lab/invisibook/ckb"
	"github.com/invisibook-lab/invisibook/config"
	"github.com/invisibook-lab/invisibook/consensus"
	"github.com/invisibook-lab/invisibook/core"
	"github.com/invisibook-lab/invisibook/store"
)

// main boots the Invisibook chain node: it loads kernel and core configs,
// constructs the PoB consensus, Account, and OrderBook tripods, then starts
// the kernel.
func main() {
	cfgPath := flag.String("config", "cfg/chain.toml", "path to chain config file")
	coreCfgPath := flag.String("core-config", "cfg/core.toml", "path to core tripod config file")
	flag.Parse()

	yuCfg := startup.InitKernelConfigFromPath(*cfgPath)

	// Core config is optional: missing or malformed files fall back to defaults
	// so a fresh node can boot without a hand-written core.toml.
	coreCfg, err := config.Load(*coreCfgPath)
	if err != nil {
		log.Printf("WARN: failed to load core config (%s), using defaults: %v", *coreCfgPath, err)
		coreCfg = config.Default()
	}

	// Derive the miner keypair. secp256k1 throughout: the same key signs L2
	// blocks, evaluates the VRF, and (via blake160 of its compressed pubkey)
	// owns the CKB address that pays on L1.
	//
	// The seed comes from the config so that `cmd/pob-miner`, which creates
	// this miner's budget cell on CKB, can arrive at the same key — V7 holds
	// that cell against the block producer, so a different key is a cell this
	// node cannot bid with.
	pubkey, privkey, err := keypair.GenKeyPairWithSecret(keypair.Secp256k1, []byte(coreCfg.Consensus.MinerSecret))
	if err != nil {
		logrus.Fatal("generate keypair failed: ", err)
	}

	// Reuse the very same secp256k1 scalar for VRF evaluation, so the VRF
	// public key is the block producer's public key by construction.
	vrfPrivKey, err := consensus.SecpPrivKeyToECDSA(privkey.Bytes())
	if err != nil {
		logrus.Fatal("derive VRF key from miner key failed: ", err)
	}

	// The three L1 interfaces are one object when CKB is configured: on chain
	// they are three views of the same two cells, and one connection reading
	// them all is what keeps them from disagreeing about which chain this
	// node is on. Without a `[ckb]` section they fall back to the in-memory
	// mock, which is what lets a lone node come up with no L1 at all.
	l1Verifier, l1Reader, l1Submitter := connectL1(&coreCfg.CKB, privkey)

	// The payment book is shared: the HTTP endpoint writes declarations into it
	// and the consensus loop takes them out at the matching height.
	paymentBook := consensus.NewPaymentBook()

	// One database, one handle: orders and cash are the same block's state.
	db, err := store.Open(coreCfg.DBPath, store.ParseGormLogLevel(coreCfg.DBLogLevel))
	if err != nil {
		logrus.Fatal("opening chain database: ", err)
	}
	if err := account.MigrateCashTable(db); err != nil {
		logrus.Fatal("migrating account tables: ", err)
	}
	if err := core.MigrateOrderTables(db); err != nil {
		logrus.Fatal("migrating orderbook tables: ", err)
	}

	// Writes are staged per block and only promoted once L1 settles the height,
	// so a block L1 rules against can be undone by dropping its staged rows.
	if err := store.MigrateStagedTable(db); err != nil {
		logrus.Fatal("migrating staging table: ", err)
	}
	// Only the commitment goes to L1; its opening lives here. A lost opening
	// forfeits the bid, so it is persisted rather than kept in memory.
	if err := store.MigrateBidTable(db); err != nil {
		logrus.Fatal("migrating bid table: ", err)
	}
	bids := store.NewBids(db)
	// Openings collected from the whole network. Fork choice reads them, so
	// they are consensus input rather than bookkeeping.
	if err := store.MigrateRevealTable(db); err != nil {
		logrus.Fatal("migrating reveal table: ", err)
	}
	reveals := store.NewReveals(db)
	pending := store.NewPending(db)
	pending.Register(account.CashApplier{})
	pending.Register(core.Appliers()...)

	accountTri := account.NewAccount(&coreCfg.Account, db, pending)
	orderBookTri := core.NewOrderBook(&coreCfg.OrderBook, db, pending)
	pobTri := consensus.NewProofOfBuy(&coreCfg.Consensus, pubkey, privkey, l1Verifier, l1Reader, vrfPrivKey, l1Submitter, bids, reveals, paymentBook, pending)

	// The payment endpoint confirms each declaration against L1 before it
	// reaches the book, so it needs the same verifier and miner identity the
	// consensus loop uses.
	paymentServer := consensus.NewPaymentServer(paymentBook, l1Verifier, consensus.MinerPubkeyHex(pubkey))
	paymentServer.Start(coreCfg.Consensus.PaymentListen)

	// Registration order decides InitChain order, and that matters for one
	// thing: the genesis block. yu's synchronizer writes its own — with a
	// hash of all zeroes, since it builds one from HexToHash("genesis") and
	// "genesis" is not hex — and the write is insert-if-absent, so whoever
	// goes first owns it. PoB therefore registers ahead of the synchronizer
	// and stores a real genesis block; see consensus.defineGenesis for what a
	// zero-hash genesis does to the chain.
	startup.InitKernel(yuCfg).
		WithTripods(pobTri, accountTri, orderBookTri, synchronizer.NewSynchronizer(yuCfg.SyncMode)).
		Startup()
}

// connectL1 returns the three interfaces the consensus reaches L1 through,
// backed by a real CKB node when one is configured and by the in-memory mock
// when none is.
//
// A misconfigured `[ckb]` section is fatal rather than a fallback to the
// mock. Falling back would leave a node that believes it is anchoring to L1
// producing blocks nobody else can verify, and the operator would learn about
// it from the network rather than from startup.
//
// `privKey` is the miner's block key, which is also the key that owns its CKB
// address — the identity binding of proof_of_buy.md §6.2 is that they are the
// same scalar.
func connectL1(cfg *ckb.Config, privKey keypair.PrivKey) (consensus.L1PaymentVerifier, consensus.L1Reader, consensus.L1CommitmentSubmitter) {
	if !cfg.Enabled {
		logrus.Warn("PoB: no [ckb] section, running against the in-memory mock L1: " +
			"payments are not real and commitments are not anchored")
		return &consensus.MockL1PaymentVerifier{}, &consensus.MockL1Reader{}, consensus.NewMockL1CommitmentSubmitter()
	}

	client, err := ckb.New(cfg, privKey.Bytes())
	if err != nil {
		logrus.Fatal("connecting to CKB failed: ", err)
	}
	logrus.Infof("PoB: anchoring to CKB at %s (%s)", cfg.RPCURL, cfg.Network)
	return client, client, client
}

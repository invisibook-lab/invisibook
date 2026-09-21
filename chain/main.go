package main

import (
	"flag"
	"log"

	"github.com/sirupsen/logrus"
	"github.com/yu-org/yu/core/keypair"
	"github.com/yu-org/yu/core/startup"

	"github.com/invisibook-lab/invisibook/account"
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

	// Generate the miner keypair for single-node mode. secp256k1 is used
	// throughout: the same key signs L2 blocks, evaluates the VRF, and (via
	// blake160 of its compressed pubkey) owns the CKB address that pays on L1.
	nodeSecret := []byte("node1")
	pubkey, privkey, err := keypair.GenKeyPairWithSecret(keypair.Secp256k1, nodeSecret)
	if err != nil {
		logrus.Fatal("generate keypair failed: ", err)
	}

	// Reuse the very same secp256k1 scalar for VRF evaluation, so the VRF
	// public key is the block producer's public key by construction.
	vrfPrivKey, err := consensus.SecpPrivKeyToECDSA(privkey.Bytes())
	if err != nil {
		logrus.Fatal("derive VRF key from miner key failed: ", err)
	}

	l1Verifier := &consensus.MockL1PaymentVerifier{}
	l1Submitter := consensus.NewMockL1CommitmentSubmitter()

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
	pending := store.NewPending(db)
	pending.Register(account.CashApplier{})
	pending.Register(core.Appliers()...)

	accountTri := account.NewAccount(&coreCfg.Account, db, pending)
	orderBookTri := core.NewOrderBook(&coreCfg.OrderBook, db, pending)
	pobTri := consensus.NewProofOfBuy(&coreCfg.Consensus, pubkey, privkey, l1Verifier, vrfPrivKey, l1Submitter, bids, paymentBook, pending)

	// The payment endpoint confirms each declaration against L1 before it
	// reaches the book, so it needs the same verifier and miner identity the
	// consensus loop uses.
	paymentServer := consensus.NewPaymentServer(paymentBook, l1Verifier, consensus.MinerPubkeyHex(pubkey))
	paymentServer.Start(coreCfg.Consensus.PaymentListen)

	startup.InitDefaultKernel(yuCfg).WithTripods(pobTri, accountTri, orderBookTri).Startup()
}

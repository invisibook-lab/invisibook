package main

import (
	"flag"
	"log"

	"github.com/sirupsen/logrus"
	"github.com/yu-org/yu/core/keypair"
	"github.com/yu-org/yu/core/startup"

	"github.com/invisibook-lab/invisibook/consensus"
	"github.com/invisibook-lab/invisibook/core"
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
	coreCfg, err := core.LoadConfig(*coreCfgPath)
	if err != nil {
		log.Printf("WARN: failed to load core config (%s), using defaults: %v", *coreCfgPath, err)
		coreCfg = core.DefaultConfig()
	}

	// Generate keypair for single-node mode (same secret as PoA default)
	pubkey, privkey, err := keypair.GenKeyPairWithSecret(keypair.Sr25519, []byte("node1"))
	if err != nil {
		logrus.Fatal("generate keypair failed: ", err)
	}

	l1Verifier := &consensus.MockL1PaymentVerifier{}
	pobTri := consensus.NewProofOfBuy(&coreCfg.Consensus, pubkey, privkey, l1Verifier)
	accountTri := core.NewAccount(&coreCfg.Account)
	orderBookTri := core.NewOrderBook(&coreCfg.OrderBook)

	startup.InitDefaultKernel(yuCfg).WithTripods(pobTri, accountTri, orderBookTri).Startup()
}

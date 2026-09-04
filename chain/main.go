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
	l1Submitter := consensus.NewMockL1HeaderSubmitter(coreCfg.Consensus.MockL1ConfirmDelay)
	pobTri := consensus.NewProofOfBuy(&coreCfg.Consensus, pubkey, privkey, l1Verifier, vrfPrivKey, l1Submitter)
	accountTri := core.NewAccount(&coreCfg.Account)
	orderBookTri := core.NewOrderBook(&coreCfg.OrderBook)

	consensus.StartPaymentServer(coreCfg.Consensus.PaymentListen)

	startup.InitDefaultKernel(yuCfg).WithTripods(pobTri, accountTri, orderBookTri).Startup()
}

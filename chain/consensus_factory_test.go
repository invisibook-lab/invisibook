package main

import (
	"github.com/invisibook-lab/invisibook/config"
	"github.com/invisibook-lab/invisibook/consensus"
	"github.com/yu-org/yu/apps/poa"
	"github.com/yu-org/yu/core/keypair"
	"testing"
)

// testPoAConfig constructs a valid single-validator development configuration.
func testPoAConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg := config.Default()
	cfg.Consensus.Engine = "poa"
	pub, _, err := keypair.GenKeyPairWithSecret(keypair.Secp256k1, []byte("node1"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.PoA = poa.PoaConfig{KeyType: keypair.Secp256k1, MySecret: "node1", BlockInterval: 10, PackNum: 10, Validators: []*poa.ValidatorConf{{Pubkey: pub.StringWithType()}}}
	return cfg
}

// TestConsensusSelection verifies engine isolation and rejects invalid selections before services start.
func TestConsensusSelection(t *testing.T) {
	cfg := testPoAConfig(t)
	// Invalid PoB-only settings must never be used by a PoA node.
	cfg.CKB.Enabled = true
	cfg.CKB.RPCURL = "invalid"
	cfg.PoB.AnchorBatchSize = 0
	selected, err := buildConsensus(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := selected.tripod.(*poa.Poa); !ok {
		t.Fatal("did not select yu PoA")
	}
	selected.start()
	cfg = config.Default()
	selected, err = buildConsensus(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := selected.tripod.(*consensus.ProofOfBuy); !ok {
		t.Fatal("did not select PoB")
	}
	cfg.Consensus.Engine = "typo"
	if _, err := buildConsensus(cfg); err == nil {
		t.Fatal("accepted unknown engine")
	}
	cfg = testPoAConfig(t)
	cfg.PoA.Validators = nil
	if _, err := buildConsensus(cfg); err == nil {
		t.Fatal("accepted empty validator set")
	}
	cfg = testPoAConfig(t)
	cfg.PoA.Validators[0].Pubkey = "invalid"
	if _, err := buildConsensus(cfg); err == nil {
		t.Fatal("accepted malformed validator")
	}
	cfg = testPoAConfig(t)
	cfg.PoA.Validators = append(cfg.PoA.Validators, cfg.PoA.Validators[0])
	if _, err := buildConsensus(cfg); err == nil {
		t.Fatal("accepted duplicate validator")
	}
}

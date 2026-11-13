package main

import (
	"fmt"
	"github.com/invisibook-lab/invisibook/ckb"
	"github.com/invisibook-lab/invisibook/config"
	"github.com/invisibook-lab/invisibook/consensus"
	"github.com/yu-org/yu/apps/poa"
	"github.com/yu-org/yu/core/keypair"
)

// selectedConsensus bundles the tripod with engine-specific services started after construction.
type selectedConsensus struct {
	tripod any
	start  func()
}

// buildConsensus constructs only the selected engine; cfg must contain all its required settings.
func buildConsensus(cfg *config.Config) (*selectedConsensus, error) {
	if err := cfg.ValidateConsensus(); err != nil {
		return nil, err
	}
	if cfg.Consensus.Engine == "poa" {
		return &selectedConsensus{tripod: poa.NewPoa(&cfg.PoA), start: func() {}}, nil
	}
	pub, priv, err := keypair.GenKeyPairWithSecret(keypair.Secp256k1, []byte(cfg.Consensus.MinerSecret))
	if err != nil {
		return nil, err
	}
	vrf, err := consensus.SecpPrivKeyToECDSA(priv.Bytes())
	if err != nil {
		return nil, err
	}
	verifier, reader, submitter, err := connectL1(&cfg.CKB, priv)
	if err != nil {
		return nil, err
	}
	book := consensus.NewPaymentBook()
	pob := consensus.NewProofOfBuy(&cfg.Consensus, pub, priv, verifier, reader, vrf, submitter, book)
	server := consensus.NewPaymentServer(book, verifier, consensus.MinerPubkeyHex(pub))
	return &selectedConsensus{tripod: pob, start: func() { server.Start(cfg.Consensus.PaymentListen) }}, nil
}

// connectL1 constructs PoB's L1 interfaces without silently falling back on invalid CKB settings.
func connectL1(cfg *ckb.Config, priv keypair.PrivKey) (consensus.L1PaymentVerifier, consensus.L1Reader, consensus.L1HeaderSubmitter, error) {
	if !cfg.Enabled {
		return &consensus.MockL1PaymentVerifier{}, &consensus.MockL1Reader{}, consensus.NewMockL1HeaderSubmitter(), nil
	}
	client, err := ckb.New(cfg, priv.Bytes())
	if err != nil {
		return nil, nil, nil, fmt.Errorf("connecting to CKB: %w", err)
	}
	return client, client, client, nil
}

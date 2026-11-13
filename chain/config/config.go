// Package config assembles the per-tripod configuration into the single file
// the node is started with.
//
// It sits above every tripod package so that none of them has to know about
// the others: consensus, orderbook and account each own their own section and
// defaults, and only this package depends on all three.
package config

import (
	"fmt"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/yu-org/yu/apps/poa"
	"github.com/yu-org/yu/core/keypair"

	"github.com/BurntSushi/toml"

	"github.com/invisibook-lab/invisibook/account"
	"github.com/invisibook-lab/invisibook/ckb"
	"github.com/invisibook-lab/invisibook/consensus"
	"github.com/invisibook-lab/invisibook/core"
)

// Config holds all configurable parameters for the chain's tripods.
//
// Database ownership and connection settings belong to yu in cfg/chain.toml.
type Config struct {
	PoA       poa.PoaConfig          `toml:"poa"`
	Consensus consensus.EngineConfig `toml:"consensus"`
	PoB       consensus.Config       `toml:"pob"`
	OrderBook core.OrderBookConfig   `toml:"orderbook"`
	Account   account.Config         `toml:"account"`
	CKB       ckb.Config             `toml:"ckb"`
}

// Default returns a Config with every section at its own default.
func Default() *Config {
	return &Config{
		Consensus: consensus.EngineConfig{Engine: "pob"},
		PoB:       consensus.DefaultConsensusConfig(),
		OrderBook: core.DefaultOrderBookConfig(),
		Account:   account.DefaultConfig(),
		CKB:       ckb.DefaultConfig(),
	}
}

// Load reads a TOML config file and returns a Config.
// Missing fields fall back to defaults.
func Load(path string) (*Config, error) {
	cfg := Default()
	metadata, err := toml.DecodeFile(path, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to load core config from %s: %w", path, err)
	}
	for _, key := range metadata.Undecoded() {
		if len(key) > 0 && key[0] == "consensus" {
			return nil, fmt.Errorf("unsupported setting %s: [consensus] only accepts engine; move PoB parameters to [pob]", key.String())
		}
	}
	if err := cfg.ValidateConsensus(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// ValidateConsensus rejects unknown engines and malformed selected-engine settings before startup.
func (c *Config) ValidateConsensus() error {
	switch c.Consensus.Engine {
	case "pob":
		_, err := consensus.NewAnchorSchedule(&c.PoB)
		return err
	case "poa":
		if c.PoA.MySecret == "" {
			return fmt.Errorf("poa requires my_secret")
		}
		if c.PoA.BlockInterval <= 0 || c.PoA.PackNum == 0 || len(c.PoA.Validators) == 0 {
			return fmt.Errorf("poa requires positive block_interval, pack_num and validators")
		}
		if _, _, err := keypair.GenKeyPairWithSecret(c.PoA.KeyType, []byte(c.PoA.MySecret)); err != nil {
			return fmt.Errorf("poa key: %w", err)
		}
		seen := make(map[string]bool)
		for _, v := range c.PoA.Validators {
			if v == nil {
				return fmt.Errorf("nil poa validator")
			}
			key, err := keypair.PubkeyFromStr(v.Pubkey)
			if err != nil {
				return fmt.Errorf("poa validator: %w", err)
			}
			identity := key.Address().String()
			if seen[identity] {
				return fmt.Errorf("duplicate poa validator")
			}
			seen[identity] = true
			if v.P2pIp != "" {
				if _, err := peer.Decode(v.P2pIp); err != nil {
					return fmt.Errorf("poa peer: %w", err)
				}
			}
		}
		return nil
	default:
		return fmt.Errorf("unknown consensus engine %q: expected poa or pob", c.Consensus.Engine)
	}
}

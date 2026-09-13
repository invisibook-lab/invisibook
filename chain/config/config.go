// Package config assembles the per-tripod configuration into the single file
// the node is started with.
//
// It sits above every tripod package so that none of them has to know about
// the others: consensus, orderbook and account each own their own section and
// defaults, and only this package depends on all three.
package config

import (
	"fmt"

	"github.com/BurntSushi/toml"

	"github.com/invisibook-lab/invisibook/account"
	"github.com/invisibook-lab/invisibook/consensus"
	"github.com/invisibook-lab/invisibook/core"
)

// Config holds all configurable parameters for the chain's tripods.
//
// `DBPath` is the one SQLite database every tripod writes through: orders and
// cash are the same block's state, so they share a file and a transaction.
type Config struct {
	DBPath     string               `toml:"db_path"`
	DBLogLevel string               `toml:"db_log_level"`
	Consensus  consensus.Config     `toml:"consensus"`
	OrderBook  core.OrderBookConfig `toml:"orderbook"`
	Account    account.Config       `toml:"account"`
}

// Default returns a Config with every section at its own default.
func Default() *Config {
	return &Config{
		DBPath:     "data/chain.db",
		DBLogLevel: "warn",
		Consensus:  consensus.DefaultConsensusConfig(),
		OrderBook:  core.DefaultOrderBookConfig(),
		Account:    account.DefaultConfig(),
	}
}

// Load reads a TOML config file and returns a Config.
// Missing fields fall back to defaults.
func Load(path string) (*Config, error) {
	cfg := Default()
	if _, err := toml.DecodeFile(path, cfg); err != nil {
		return nil, fmt.Errorf("failed to load core config from %s: %w", path, err)
	}
	return cfg, nil
}

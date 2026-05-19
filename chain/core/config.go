package core

import (
	"fmt"

	"github.com/BurntSushi/toml"
)

// Config holds all configurable parameters for the core tripods.
type Config struct {
	OrderBook OrderBookConfig `toml:"orderbook"`
	Account   AccountConfig   `toml:"account"`
}

// OrderBookConfig holds configuration for the OrderBook tripod.
//
// `SplitVKPath` is the snarkjs `vk.json` for the split circuit (SendOrder).
// `SettleLargerVKPath` is the settle circuit for the larger side (change +
// cross-leg ratio check). Only the larger party submits a ZK proof; the
// smaller party confirms settlement without proof.
type OrderBookConfig struct {
	DBPath             string `toml:"db_path"`
	SplitVKPath        string `toml:"split_vk_path"`
	SettleLargerVKPath string `toml:"settle_larger_vk_path"`
}

// AccountConfig holds configuration for the Account tripod.
//
// `DepositVKPath` and `WithdrawVKPath` point at the snarkjs `vk.json` files
// produced by `snarkjs zkey export verificationkey <circuit>.zkey vk.json`.
// Both are required at startup — chain refuses to boot if any path is unset
// or the file is missing/malformed.
type AccountConfig struct {
	DBPath         string        `toml:"db_path"`
	DepositVKPath  string        `toml:"deposit_vk_path"`
	WithdrawVKPath string        `toml:"withdraw_vk_path"`
	GenesisCash    []GenesisCash `toml:"genesis_cash"`
}

// GenesisCash defines a Cash record to be inserted at chain initialization.
// The ID is explicit — no derivation happens on-chain.
type GenesisCash struct {
	ID     string `toml:"id"`
	Pubkey string `toml:"pubkey"`
	Token  string `toml:"token"`
	Amount string `toml:"amount"`
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		OrderBook: OrderBookConfig{
			DBPath: "orders.db",
		},
		Account: AccountConfig{
			DBPath: "accounts.db",
		},
	}
}

// LoadConfig reads a TOML config file and returns a Config.
// Missing fields fall back to defaults.
func LoadConfig(path string) (*Config, error) {
	cfg := DefaultConfig()
	if _, err := toml.DecodeFile(path, cfg); err != nil {
		return nil, fmt.Errorf("failed to load core config from %s: %w", path, err)
	}
	return cfg, nil
}

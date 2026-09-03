package core

import (
	"fmt"
	"strings"

	"github.com/BurntSushi/toml"
	"gorm.io/gorm/logger"
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
// `SettleCoZkVKPath` is the joint settle_cozk circuit whose single proof is
// generated collaboratively by both traders (SettleOrdersCoZk writing).
// `SettleCoZk2pVKPath` is the ark-compressed PLONK verifying key of the
// 2-party collaborative settlement (SettleOrdersCoZk2p writing; verification
// requires a chain binary built with `-tags cozk2p`).
// `RequireProofs`, when true, makes an empty/missing settlement VK path a
// startup error instead of silently skipping verification (see LoadVK's
// fail-open contract). Leave false for test/dev configs that intentionally
// run without circuit artifacts; set true in production so a misconfigured
// node refuses to boot rather than accept unverified settlements.
// `DBLogLevel` controls GORM SQL logging: "silent", "error", "warn", "info".
type OrderBookConfig struct {
	DBPath             string `toml:"db_path"`
	SplitVKPath        string `toml:"split_vk_path"`
	SettleLargerVKPath string `toml:"settle_larger_vk_path"`
	SettleCoZkVKPath   string `toml:"settle_cozk_vk_path"`
	SettleCoZk2pVKPath string `toml:"settle_cozk2p_vk_path"`
	RequireProofs      bool   `toml:"require_proofs"`
	DBLogLevel         string `toml:"db_log_level"`
}

// AccountConfig holds configuration for the Account tripod.
//
// `DepositVKPath` and `WithdrawVKPath` point at the snarkjs `vk.json` files
// produced by `snarkjs zkey export verificationkey <circuit>.zkey vk.json`.
// Both are required at startup — chain refuses to boot if any path is unset
// or the file is missing/malformed.
// `DBLogLevel` controls GORM SQL logging: "silent", "error", "warn", "info".
type AccountConfig struct {
	DBPath         string        `toml:"db_path"`
	DepositVKPath  string        `toml:"deposit_vk_path"`
	WithdrawVKPath string        `toml:"withdraw_vk_path"`
	DBLogLevel     string        `toml:"db_log_level"`
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
// DBLogLevel defaults to "warn" to suppress expected "record not found" noise.
func DefaultConfig() *Config {
	return &Config{
		OrderBook: OrderBookConfig{
			DBPath:     "orders.db",
			DBLogLevel: "warn",
		},
		Account: AccountConfig{
			DBPath:     "accounts.db",
			DBLogLevel: "warn",
		},
	}
}

// ParseGormLogLevel converts a string log level to gorm logger.LogLevel.
// Accepted values: "silent", "error", "warn", "info". Defaults to Warn.
func ParseGormLogLevel(level string) logger.LogLevel {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "silent":
		return logger.Silent
	case "error":
		return logger.Error
	case "info":
		return logger.Info
	default:
		return logger.Warn
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

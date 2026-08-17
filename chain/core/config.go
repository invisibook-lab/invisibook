package core

import (
	"fmt"
	"strings"

	"github.com/BurntSushi/toml"
	"gorm.io/gorm/logger"
)

// Config holds all configurable parameters for the core tripods.
// `ChainID` enters every bind transcript so proofs cannot replay across
// chains; it must equal the yu kernel's chain id.
type Config struct {
	ChainID   uint64          `toml:"chain_id"`
	OrderBook OrderBookConfig `toml:"orderbook"`
	Account   AccountConfig   `toml:"account"`
}

// OrderBookConfig holds configuration for the OrderBook tripod.
//
// `SettleCoZkVKPath` is the joint settle_cozk circuit whose single proof is
// generated collaboratively by both traders (SubmitCompareCoZk writing).
// `SettleCoZk2pVKPath` is the ark-compressed PLONK verifying key of the
// 2-party collaborative settlement (SubmitCompareCoZk2p writing; verification
// requires a chain binary built with `-tags cozk2p`).
// `RequireProofs` defaults to TRUE: an empty/missing settlement VK path is
// a startup error instead of silently skipping verification (see LoadVK's
// fail-open contract). Dev/test configs that intentionally run without
// circuit artifacts must OPT OUT explicitly with `require_proofs = false`;
// a config that simply forgets its VK paths refuses to boot.
// `DBLogLevel` controls GORM SQL logging: "silent", "error", "warn", "info".
type OrderBookConfig struct {
	DBPath             string `toml:"db_path"`
	SettleCoZkVKPath   string `toml:"settle_cozk_vk_path"`
	SettleCoZk2pVKPath string `toml:"settle_cozk2p_vk_path"`
	SettleSmallVKPath  string `toml:"settle_small_vk_path"`
	SettleLargeVKPath  string `toml:"settle_large_vk_path"`
	SendOrderVKPath    string `toml:"send_order_vk_path"`
	ClaimFeesVKPath    string `toml:"claim_fees_vk_path"`
	RequireProofs      bool   `toml:"require_proofs"`
	DBLogLevel         string `toml:"db_log_level"`
	ChainID            uint64 `toml:"-"`
}

// AccountConfig holds configuration for the Account tripod.
//
// `NoteDepositVKPath`/`SpendWithdrawVKPath` are the shielded-pool circuits
// (snarkjs `vk.json` files).
// `BridgeOperatorPubkey` (64-char ed25519 hex) gates NoteDeposit until the
// real bridge inclusion proof lands: when set, every deposit must carry the
// operator's signature; when empty, the check is skipped (dev only — a
// public network MUST set it).
// `RequireProofs` mirrors the OrderBook flag (default TRUE): an empty VK
// path becomes a startup error; dev mode needs an explicit
// `require_proofs = false`.
// `DBLogLevel` controls GORM SQL logging: "silent", "error", "warn", "info".
// `ChainID` is copied from the top-level config by LoadConfig.
type AccountConfig struct {
	DBPath               string        `toml:"db_path"`
	NoteDepositVKPath    string        `toml:"note_deposit_vk_path"`
	SpendWithdrawVKPath  string        `toml:"spend_withdraw_vk_path"`
	BridgeOperatorPubkey string        `toml:"bridge_operator_pubkey"`
	RequireProofs        bool          `toml:"require_proofs"`
	DBLogLevel           string        `toml:"db_log_level"`
	GenesisNote          []GenesisNote `toml:"genesis_note"`
	ChainID              uint64        `toml:"-"`
}

// GenesisNote defines one shielded-pool leaf seeded at chain init. Leaves
// are appended in listing order as leaves 0..len-1; the seeding is
// prefix-verified so a restart never duplicates or shifts them. `Memo` is
// documentation only (e.g. "alice 2000 ETH") — the chain never parses it.
type GenesisNote struct {
	Cm   string `toml:"cm"`
	Memo string `toml:"memo"`
}

// DefaultConfig returns a Config with sensible SECURE defaults: proof
// verification is required, so a configuration that carries no verifying
// keys refuses to boot instead of silently skipping verification. Dev/test
// configs opt out with an explicit `require_proofs = false`.
// DBLogLevel defaults to "warn" to suppress expected "record not found" noise.
func DefaultConfig() *Config {
	return &Config{
		ChainID: 1926,
		OrderBook: OrderBookConfig{
			DBPath:        "orders.db",
			DBLogLevel:    "warn",
			RequireProofs: true,
		},
		Account: AccountConfig{
			DBPath:        "accounts.db",
			DBLogLevel:    "warn",
			RequireProofs: true,
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
	// Propagate the chain id into the per-tripod configs (bind transcripts).
	cfg.Account.ChainID = cfg.ChainID
	cfg.OrderBook.ChainID = cfg.ChainID
	return cfg, nil
}

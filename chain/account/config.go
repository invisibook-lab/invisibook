package account

import (
	"strings"

	"gorm.io/gorm/logger"
)

// Config holds configuration for the Account tripod.
//
// `DepositVKPath` and `WithdrawVKPath` point at the snarkjs `vk.json` files
// produced by `snarkjs zkey export verificationkey <circuit>.zkey vk.json`.
// Both are required at startup — chain refuses to boot if any path is unset
// or the file is missing/malformed.
// `DBLogLevel` controls GORM SQL logging: "silent", "error", "warn", "info".
type Config struct {
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

// DefaultConfig returns an account Config with sensible defaults.
func DefaultConfig() Config {
	return Config{DBPath: "accounts.db", DBLogLevel: "warn"}
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

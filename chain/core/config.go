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
type OrderBookConfig struct {
	DBPath string `toml:"db_path"`
}

// AccountConfig holds configuration for the Account tripod.
type AccountConfig struct {
	DBPath          string           `toml:"db_path"`
	GenesisAccounts []GenesisAccount `toml:"genesis_accounts"`
}

// GenesisAccount defines a pre-funded account seeded at chain initialization.
type GenesisAccount struct {
	Address string `toml:"address"`
	Token   string `toml:"token"`
	Amount  string `toml:"amount"`
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

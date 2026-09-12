package core

// OrderBookConfig holds configuration for the OrderBook tripod.
//
// `SplitVKPath` is the snarkjs `vk.json` for the split circuit (SendOrder).
// `SettleLargerVKPath` is the settle circuit for the larger side (change +
// cross-leg ratio check). Only the larger party submits a ZK proof; the
// smaller party confirms settlement without proof.
// `DBLogLevel` controls GORM SQL logging: "silent", "error", "warn", "info".
type OrderBookConfig struct {
	DBPath             string `toml:"db_path"`
	SplitVKPath        string `toml:"split_vk_path"`
	SettleLargerVKPath string `toml:"settle_larger_vk_path"`
	DBLogLevel         string `toml:"db_log_level"`
}

// DefaultOrderBookConfig returns an orderbook Config with sensible defaults.
func DefaultOrderBookConfig() OrderBookConfig {
	return OrderBookConfig{DBPath: "orders.db", DBLogLevel: "warn"}
}

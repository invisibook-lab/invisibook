package core

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
// startup error instead of silently skipping verification (see account.LoadVK's
// fail-open contract). Leave false for test/dev configs that intentionally
// run without circuit artifacts; set true in production so a misconfigured
// node refuses to boot rather than accept unverified settlements.
type OrderBookConfig struct {
	SplitVKPath        string `toml:"split_vk_path"`
	SettleLargerVKPath string `toml:"settle_larger_vk_path"`
	SettleCoZkVKPath   string `toml:"settle_cozk_vk_path"`
	SettleCoZk2pVKPath string `toml:"settle_cozk2p_vk_path"`
	RequireProofs      bool   `toml:"require_proofs"`
}

// DefaultOrderBookConfig returns an orderbook Config with sensible defaults.
func DefaultOrderBookConfig() OrderBookConfig {
	return OrderBookConfig{}
}

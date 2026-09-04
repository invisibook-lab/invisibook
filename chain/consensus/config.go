package consensus

// Config holds all configurable parameters for the Proof-of-Buy consensus.
type Config struct {
	// MinPayment is the minimum L1 payment amount (decimal string).
	MinPayment string `toml:"min_payment"`
	// FinalityPeriod is the number of L2 blocks per finality cycle.
	FinalityPeriod uint64 `toml:"finality_period"`
	// BlockInterval is the target block time in milliseconds.
	BlockInterval int `toml:"block_interval"`
	// PackNum is the maximum number of transactions to pack per block.
	PackNum uint64 `toml:"pack_num"`
	// PaymentListen is the listen address for the gin payment HTTP server.
	PaymentListen string `toml:"payment_listen"`
	// L1PollInterval is the interval in milliseconds for polling L1 confirmation.
	L1PollInterval int `toml:"l1_poll_interval"`
	// MockL1ConfirmDelay is the simulated L1 confirmation delay in milliseconds.
	MockL1ConfirmDelay int `toml:"mock_l1_confirm_delay"`
}

// DefaultConsensusConfig returns a Config with sensible defaults.
func DefaultConsensusConfig() Config {
	return Config{
		MinPayment:         "100",
		FinalityPeriod:     10,
		BlockInterval:      3000,
		PackNum:            30000,
		PaymentListen:      ":8081",
		L1PollInterval:     1000,
		MockL1ConfirmDelay: 2000,
	}
}

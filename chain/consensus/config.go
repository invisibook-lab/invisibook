package consensus

// Config holds all configurable parameters for the Proof-of-Buying consensus.
type Config struct {
	// VDFDifficulty is the number of SHA256 iterations for the VDF.
	VDFDifficulty uint64 `toml:"vdf_difficulty"`
	// MinPayment is the minimum L1 payment amount (decimal string).
	MinPayment string `toml:"min_payment"`
	// FinalityPeriod is the number of L2 blocks per finality cycle.
	FinalityPeriod uint64 `toml:"finality_period"`
	// BlockInterval is the target block time in milliseconds.
	BlockInterval int `toml:"block_interval"`
	// PackNum is the maximum number of transactions to pack per block.
	PackNum uint64 `toml:"pack_num"`
}

// DefaultConsensusConfig returns a Config with sensible defaults.
func DefaultConsensusConfig() Config {
	return Config{
		VDFDifficulty:  1000,
		MinPayment:     "100",
		FinalityPeriod: 10,
		BlockInterval:  3000,
		PackNum:        30000,
	}
}

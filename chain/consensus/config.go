package consensus

// Config holds all configurable parameters for the Proof-of-Buying consensus.
type Config struct {
	// VDFDifficulty is the number of squaring iterations for the Wesolowski VDF.
	// Linearly controls computation delay (~1.1ms per iteration).
	VDFDifficulty uint64 `toml:"vdf_difficulty"`
	// MinPayment is the minimum L1 payment amount (decimal string).
	MinPayment string `toml:"min_payment"`
	// FinalityPeriod is the number of L2 blocks per finality cycle.
	FinalityPeriod uint64 `toml:"finality_period"`
	// BlockInterval is the target block time in milliseconds.
	BlockInterval int `toml:"block_interval"`
	// PackNum is the maximum number of transactions to pack per block.
	PackNum uint64 `toml:"pack_num"`
	// FiberRPCUrl is the Fiber node JSON-RPC endpoint for send_payment.
	FiberRPCUrl string `toml:"fiber_rpc_url"`
	// PaymentListen is the listen address for the gin payment HTTP server.
	PaymentListen string `toml:"payment_listen"`
}

// DefaultConsensusConfig returns a Config with sensible defaults.
func DefaultConsensusConfig() Config {
	return Config{
		VDFDifficulty:  1000,
		MinPayment:     "100",
		FinalityPeriod: 10,
		BlockInterval:  3000,
		PackNum:        30000,
		FiberRPCUrl:    "http://127.0.0.1:8227",
		PaymentListen:  ":8081",
	}
}

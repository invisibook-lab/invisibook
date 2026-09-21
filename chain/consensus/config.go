package consensus

// Config holds all configurable parameters for the Proof-of-Buy consensus.
type Config struct {
	// MinPayment is the minimum L1 payment amount (decimal string), used as
	// the fallback bid when RequireDeclaredPayment is off.
	MinPayment string `toml:"min_payment"`
	// CoinbaseReward is the fixed native-token reward a block pays its
	// producer, on top of the handling fees it collected (decimal string).
	CoinbaseReward string `toml:"coinbase_reward"`
	// RequireDeclaredPayment makes a height with no confirmed declaration a
	// round this node sits out, which is the protocol behaviour. Turn it off
	// only for development against a mock L1, where no declaration can ever be
	// confirmed and a lone node would otherwise never produce a block.
	RequireDeclaredPayment bool `toml:"require_declared_payment"`
	// BlockInterval is the target block time in milliseconds.
	BlockInterval int `toml:"block_interval"`
	// PackNum is the maximum number of transactions to pack per block.
	PackNum uint64 `toml:"pack_num"`
	// PaymentListen is the listen address for the gin payment HTTP server.
	PaymentListen string `toml:"payment_listen"`
	// L1PollInterval is the interval in milliseconds for polling L1 depth.
	L1PollInterval int `toml:"l1_poll_interval"`
	// L1FinalityDepth is how many L1 blocks must be mined on top of a block's
	// commitment before that block is finalized. Promotion is irreversible, so
	// this depth is what stands between the chain and an L1 reorg taking a
	// commitment back off chain after its state was already written.
	L1FinalityDepth uint64 `toml:"l1_finality_depth"`
	// MockL1BlockTime is the simulated L1 block interval in milliseconds, used
	// by the mock submitter to grow a submission's depth over time.
	MockL1BlockTime int `toml:"mock_l1_block_time"`
}

// DefaultConsensusConfig returns a Config with sensible defaults.
func DefaultConsensusConfig() Config {
	return Config{
		MinPayment:             "100",
		RequireDeclaredPayment: true,
		CoinbaseReward:         "0",
		BlockInterval:          3000,
		PackNum:                30000,
		PaymentListen:          ":8081",
		L1PollInterval:         1000,
		L1FinalityDepth:        24,
		MockL1BlockTime:        200,
	}
}

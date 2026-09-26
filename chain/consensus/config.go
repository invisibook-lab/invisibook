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
	// L1PollInterval is the interval in milliseconds at which the finality
	// worker asks L1 whether a commitment has landed.
	L1PollInterval int `toml:"l1_poll_interval"`
	// MinerSecret is the seed the node's miner keypair is derived from.
	//
	// One key wears three hats — it signs L2 blocks, evaluates the VRF, and
	// owns the CKB address that pays on L1 — so whatever creates this
	// miner's budget cell has to derive the very same key, or V7 will hold
	// the cell against a stranger. `cmd/pob-miner` reads it from here for
	// exactly that reason.
	//
	// A seed rather than a key, and a plain one at that: this is a
	// development convenience, not key management. A real deployment wants
	// the key held somewhere it can be protected.
	MinerSecret string `toml:"miner_secret"`
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
		MinerSecret:            "node1",
	}
}

package account

// Config holds configuration for the Account tripod.
//
// `DepositVKPath` and `WithdrawVKPath` point at the snarkjs `vk.json` files
// produced by `snarkjs zkey export verificationkey <circuit>.zkey vk.json`.
// Both are required at startup — chain refuses to boot if any path is unset
// or the file is missing/malformed.
// `DBLogLevel` controls GORM SQL logging: "silent", "error", "warn", "info".
type Config struct {
	DepositVKPath  string        `toml:"deposit_vk_path"`
	WithdrawVKPath string        `toml:"withdraw_vk_path"`
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
	return Config{}
}

package ckb

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/nervosnetwork/ckb-sdk-go/v2/address"
	"github.com/nervosnetwork/ckb-sdk-go/v2/systemscript"
	ckbtypes "github.com/nervosnetwork/ckb-sdk-go/v2/types"
)

// Config is the `[ckb]` section of the node's core config: where CKB is, and
// which scripts this L2 chain's cells are guarded by.
//
// Nothing here has a useful default. The four PoB scripts are deployed per
// chain, so their code hashes and cell deps are facts about a particular
// deployment; shipping placeholder values would only let a node start against
// scripts that do not exist and fail later, somewhere less obvious.
type Config struct {
	// Enabled switches the node from the in-memory mock L1 to a real CKB
	// node. Off by default so that `go run .` still comes up without one.
	Enabled bool `toml:"enabled"`

	// RPCURL is the CKB node's JSON-RPC endpoint. The indexer RPCs
	// (`get_cells`) have to be served from it too, which a modern ckb node
	// does by default.
	RPCURL string `toml:"rpc_url"`

	// Network is "mainnet", "testnet" or "devnet". It selects the address
	// format and the system script cell deps.
	//
	// A devnet is treated as a testnet everywhere but the sighash cell dep:
	// it shares the `ckt` address prefix, and its system scripts are the same
	// binaries under the same code hashes, but they sit in that chain's own
	// genesis transaction — hence SighashDepTxHash below.
	Network string `toml:"network"`

	// SighashDepTxHash overrides the transaction holding the
	// secp256k1_blake160_sighash_all dep group. Required on a devnet, where
	// the genesis transaction differs per chain; ignored elsewhere.
	//
	// `ckb list-hashes -c <spec>` prints it, as does the `ckb-cli` output for
	// the dev chain.
	SighashDepTxHash string `toml:"sighash_dep_tx_hash"`

	// MiningAddr is the address whose lock guards the mining addr cell — where
	// every miner's prepayment lands (ckb_layout.md §4).
	//
	// Given as an address rather than a lock hash because both forms are
	// needed: the hash goes into the budget script's args, and the script
	// itself has to be reconstructed to build the prepayment output. An
	// address carries the script, and the hash follows from it.
	MiningAddr string `toml:"mining_addr"`

	// The four deployed PoB scripts. Only their code and their cell deps are
	// configured: every args among them is derived, because they form a chain
	// — pob-spent is parameterised by the mining addr, pob-vault by the
	// resulting spent script hash, pob-budget by both plus the sighash code
	// hash. Writing those out by hand would be three chances to deploy a node
	// that reads one chain's cells and writes another's, with nothing to
	// catch it until real money had been spent.
	Budget ScriptConfig `toml:"budget_script"`
	Commit ScriptConfig `toml:"commit_script"`
	Vault  ScriptConfig `toml:"vault_script"`
	Spent  ScriptConfig `toml:"spent_script"`

	// FeeRate is the fee in shannon per 1000 bytes of transaction.
	FeeRate uint64 `toml:"fee_rate"`
}

// ScriptConfig locates one deployed script: what a cell's type field should
// say, and where the code backing it lives.
type ScriptConfig struct {
	// CodeHash identifies the script, as 0x-prefixed hex.
	CodeHash string `toml:"code_hash"`
	// HashType is "type", "data", "data1" or "data2".
	HashType string `toml:"hash_type"`
	// DepTxHash is the transaction that published the code.
	DepTxHash string `toml:"dep_tx_hash"`
	// DepIndex is the output index of the cell holding it.
	DepIndex uint32 `toml:"dep_index"`
	// DepType is "code" for a plain code cell or "dep_group" for a group.
	DepType string `toml:"dep_type"`
}

// DefaultConfig returns the config a node runs with when no `[ckb]` section
// is present: the mock L1, and a fee rate that only matters once it is not.
func DefaultConfig() Config {
	return Config{
		Enabled: false,
		Network: "devnet",
		FeeRate: 1000,
	}
}

// settings is Config after parsing: every hash decoded, every script built,
// every cell dep resolved, so that nothing downstream re-parses hex or has to
// decide what an empty field meant.
type settings struct {
	network ckbtypes.Network
	feeRate uint64

	// miningAddrLock is the lock the prepayment is paid to, and
	// miningAddrLockHash is what the budget script's args carries.
	miningAddrLock     *ckbtypes.Script
	miningAddrLockHash ckbtypes.Hash

	// spentTypeHash marks a token that has left the mining addr. Inputs
	// carrying it can never fund a budget cell (R3.4). Derived, not
	// configured — see deriveArgs.
	spentTypeHash ckbtypes.Hash

	// The four PoB scripts, each with its args filled in, and the deps that
	// make them runnable. A type script runs when its cell is created, not
	// only when it is spent, so every script a transaction puts on an output
	// needs its dep in that transaction.
	//
	// spentDep is the exception: nothing here spends or creates a marked
	// token — that is the operator paying itself out, not a miner mining —
	// so it is carried for the sake of a complete description of the
	// deployment, and for whatever builds that transaction later.
	budgetScript *ckbtypes.Script
	budgetDep    *ckbtypes.CellDep
	commitScript *ckbtypes.Script
	commitDep    *ckbtypes.CellDep
	vaultScript  *ckbtypes.Script
	vaultDep     *ckbtypes.CellDep
	spentScript  *ckbtypes.Script
	spentDep     *ckbtypes.CellDep

	// sighashCodeHash and sighashDep describe the standard lock every cell
	// this package creates is owned by, and which R3.5 pins the budget cell
	// to.
	sighashCodeHash ckbtypes.Hash
	sighashDep      *ckbtypes.CellDep
}

// resolve parses and cross-checks a Config, returning the settings the client
// runs on.
//
// It is strict on purpose. Every field here names something already deployed,
// so a value that does not parse is a misconfiguration the node cannot
// recover from at runtime — and a node that starts against the wrong script
// would commit real money to cells nobody can open.
func (c *Config) resolve() (*settings, error) {
	network, sighashDep, err := resolveNetwork(c.Network, c.SighashDepTxHash)
	if err != nil {
		return nil, err
	}

	if c.MiningAddr == "" {
		return nil, errors.New("ckb: mining_addr is required")
	}
	miningAddr, err := address.Decode(c.MiningAddr)
	if err != nil {
		return nil, fmt.Errorf("ckb: decoding mining_addr: %w", err)
	}

	commitScript, commitDep, err := c.Commit.resolve()
	if err != nil {
		return nil, fmt.Errorf("ckb: commit_script: %w", err)
	}
	budgetScript, budgetDep, err := c.Budget.resolve()
	if err != nil {
		return nil, fmt.Errorf("ckb: budget_script: %w", err)
	}
	vaultScript, vaultDep, err := c.Vault.resolve()
	if err != nil {
		return nil, fmt.Errorf("ckb: vault_script: %w", err)
	}
	spentScript, spentDep, err := c.Spent.resolve()
	if err != nil {
		return nil, fmt.Errorf("ckb: spent_script: %w", err)
	}

	out := &settings{
		network:            network,
		feeRate:            c.FeeRate,
		miningAddrLock:     miningAddr.Script,
		miningAddrLockHash: miningAddr.Script.Hash(),
		budgetScript:       budgetScript,
		budgetDep:          budgetDep,
		commitScript:       commitScript,
		commitDep:          commitDep,
		vaultScript:        vaultScript,
		vaultDep:           vaultDep,
		spentScript:        spentScript,
		spentDep:           spentDep,
		sighashCodeHash:    sighashCodeHashFor(network),
		sighashDep:         sighashDep,
	}
	if out.feeRate == 0 {
		out.feeRate = DefaultConfig().FeeRate
	}
	out.deriveArgs()
	return out, nil
}

// deriveArgs parameterises the three scripts that take args, in the order
// their dependencies force.
//
// The order is the point. pob-spent has to know the mining addr to recognise
// a token trying to go back to it; pob-vault has to know the resulting spent
// script to tell a marked payout from its own change; pob-budget has to know
// both, plus the sighash code hash R3.5 pins the lock to. Each step therefore
// consumes the hash the one before it produced, and computing them here — off
// one address — is what keeps every script in this node's world describing
// the same chain.
func (s *settings) deriveArgs() {
	s.spentScript.Args = s.miningAddrLockHash.Bytes()
	s.spentTypeHash = s.spentScript.Hash()

	s.vaultScript.Args = s.spentTypeHash.Bytes()

	budget := make([]byte, 0, 3*ckbtypes.HashLength)
	budget = append(budget, s.miningAddrLockHash.Bytes()...)
	budget = append(budget, s.spentTypeHash.Bytes()...)
	budget = append(budget, s.sighashCodeHash.Bytes()...)
	s.budgetScript.Args = budget
}

// resolve turns one script section into the script and the cell dep that
// makes it runnable. The script comes back with no args; the caller fills in
// whatever that particular script is parameterised by.
func (s *ScriptConfig) resolve() (*ckbtypes.Script, *ckbtypes.CellDep, error) {
	codeHash, err := parseHash(s.CodeHash)
	if err != nil {
		return nil, nil, fmt.Errorf("code_hash: %w", err)
	}
	hashType, err := parseHashType(s.HashType)
	if err != nil {
		return nil, nil, err
	}
	depTxHash, err := parseHash(s.DepTxHash)
	if err != nil {
		return nil, nil, fmt.Errorf("dep_tx_hash: %w", err)
	}
	depType, err := parseDepType(s.DepType)
	if err != nil {
		return nil, nil, err
	}

	script := &ckbtypes.Script{CodeHash: codeHash, HashType: hashType}
	dep := &ckbtypes.CellDep{
		OutPoint: &ckbtypes.OutPoint{TxHash: depTxHash, Index: s.DepIndex},
		DepType:  depType,
	}
	return script, dep, nil
}

// resolveNetwork maps the configured network name onto the SDK's notion of
// one, and onto the cell dep holding the standard lock.
//
// A devnet rides on the testnet's address format and code hashes — the system
// scripts are the same binaries — so only the dep out point has to be told,
// and it has to be told, since it is that chain's own genesis transaction.
func resolveNetwork(name, sighashDepTxHash string) (ckbtypes.Network, *ckbtypes.CellDep, error) {
	dep := func(txHash ckbtypes.Hash) *ckbtypes.CellDep {
		return &ckbtypes.CellDep{
			OutPoint: &ckbtypes.OutPoint{TxHash: txHash, Index: 0},
			DepType:  ckbtypes.DepTypeDepGroup,
		}
	}

	switch strings.ToLower(name) {
	case "mainnet":
		return ckbtypes.NetworkMain, dep(mainnetSighashDepTx), nil
	case "testnet":
		return ckbtypes.NetworkTest, dep(testnetSighashDepTx), nil
	case "devnet":
		if sighashDepTxHash == "" {
			return 0, nil, errors.New("ckb: sighash_dep_tx_hash is required on a devnet, " +
				"since the genesis transaction differs per chain")
		}
		txHash, err := parseHash(sighashDepTxHash)
		if err != nil {
			return 0, nil, fmt.Errorf("ckb: sighash_dep_tx_hash: %w", err)
		}
		return ckbtypes.NetworkTest, dep(txHash), nil
	default:
		return 0, nil, fmt.Errorf("ckb: unknown network %q, want mainnet, testnet or devnet", name)
	}
}

// sighashCodeHashFor returns the code hash of the standard lock on a network.
//
// A devnet resolves to the testnet here, which is right: its system scripts
// are the same binaries under the same code hashes, published into its own
// genesis. Only where they sit differs, and that is the cell dep.
func sighashCodeHashFor(network ckbtypes.Network) ckbtypes.Hash {
	return systemscript.GetCodeHash(network, systemscript.Secp256k1Blake160SighashAll)
}

// The transactions holding the secp256k1_blake160_sighash_all dep group on
// the public networks. They are part of each chain's genesis, so they are
// constants rather than configuration.
var (
	mainnetSighashDepTx = ckbtypes.HexToHash("0x71a7ba8fc96349fea0ed3a5c47992e3b4084b031a42264a018e0072e8172e46c")
	testnetSighashDepTx = ckbtypes.HexToHash("0xf8de3bb47d055cdf460d93a2a6e1b05f7432f9777c8c474abf4eec1d4aee5d37")
)

// parseHash decodes a 0x-prefixed 32-byte hex hash.
// The string must name a full hash; a short one is an error rather than
// something to left-pad, since every hash here identifies something deployed.
func parseHash(s string) (ckbtypes.Hash, error) {
	raw, err := parseBytes(s)
	if err != nil {
		return ckbtypes.Hash{}, err
	}
	if len(raw) != ckbtypes.HashLength {
		return ckbtypes.Hash{}, fmt.Errorf("want %d bytes, got %d", ckbtypes.HashLength, len(raw))
	}
	var out ckbtypes.Hash
	copy(out[:], raw)
	return out, nil
}

// parseBytes decodes an optionally 0x-prefixed hex string. An empty string
// decodes to no bytes, which is how a script with no args is written.
func parseBytes(s string) ([]byte, error) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "0x")
	if s == "" {
		return nil, nil
	}
	raw, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("not hex: %w", err)
	}
	return raw, nil
}

// parseHashType maps the configured string onto CKB's script hash type.
func parseHashType(s string) (ckbtypes.ScriptHashType, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "type":
		return ckbtypes.HashTypeType, nil
	case "data":
		return ckbtypes.HashTypeData, nil
	case "data1":
		return ckbtypes.HashTypeData1, nil
	case "data2":
		return ckbtypes.HashTypeData2, nil
	default:
		return "", fmt.Errorf("hash_type: unknown value %q", s)
	}
}

// parseDepType maps the configured string onto CKB's cell dep type.
func parseDepType(s string) (ckbtypes.DepType, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "code":
		return ckbtypes.DepTypeCode, nil
	case "dep_group":
		return ckbtypes.DepTypeDepGroup, nil
	default:
		return "", fmt.Errorf("dep_type: unknown value %q, want code or dep_group", s)
	}
}

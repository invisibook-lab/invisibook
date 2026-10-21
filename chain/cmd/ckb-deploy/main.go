// Command ckb-deploy publishes the four PoB scripts to a CKB chain and
// prints the `[ckb]` config section a node needs to talk to them.
//
// It exists because those four scripts have no fixed addresses: they are
// deployed per chain, and a devnet gets a fresh set every time it is wiped.
// Copying code hashes by hand is how a node ends up reading one chain's cells
// and writing another's, which is a mistake that costs real capacity before
// anyone notices.
//
// Typical use against a local devnet:
//
//	go run ./cmd/ckb-deploy \
//	  -rpc http://127.0.0.1:8114 \
//	  -network devnet \
//	  -sighash-dep 0x… \
//	  -mining-addr ckt1… \
//	  -core-config cfg/core.toml >> cfg/core.toml
//
// The key pays for the deployment and owns the resulting code cells, so that
// the capacity can be reclaimed when the chain is torn down. On a devnet it
// is derived from the node's own miner secret (-core-config); anywhere else
// it comes from a file (-key-file), read from disk rather than a flag because
// a private key in a flag ends up in the shell history and in every `ps`
// listing on the machine.
package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/yu-org/yu/core/keypair"

	"github.com/invisibook-lab/invisibook/ckb"
	"github.com/invisibook-lab/invisibook/config"
)

// contracts are the four scripts, in the order they are published. The order
// is only cosmetic — each cell's index comes back from the deployer — but it
// keeps the printed config stable between runs.
var contracts = []string{"pob-budget", "pob-submission", "pob-vault", "pob-spent"}

// tomlKey maps a contract onto the config section that describes it.
var tomlKey = map[string]string{
	"pob-budget":     "budget_script",
	"pob-submission": "commit_script",
	"pob-vault":      "vault_script",
	"pob-spent":      "spent_script",
}

func main() {
	rpcURL := flag.String("rpc", "http://127.0.0.1:8114", "CKB node JSON-RPC endpoint")
	network := flag.String("network", "devnet", "mainnet, testnet or devnet")
	sighashDep := flag.String("sighash-dep", "",
		"transaction holding the sighash dep group; required on a devnet")
	miningAddr := flag.String("mining-addr", "",
		"address the mining addr cell is locked to; echoed into the printed config")
	keyFile := flag.String("key-file", "",
		"file holding the deployer's secp256k1 private key as hex")
	coreConfig := flag.String("core-config", "",
		"derive the deployer key from this node config's miner_secret instead of -key-file (development only)")
	contractsDir := flag.String("contracts", "../ckb/contracts",
		"directory holding the compiled contracts")
	feeRate := flag.Uint64("fee-rate", 1000, "fee in shannon per 1000 bytes")
	flag.Parse()

	if (*keyFile == "") == (*coreConfig == "") {
		fmt.Fprintln(os.Stderr, "ckb-deploy: give exactly one of -key-file or -core-config")
		flag.Usage()
		os.Exit(2)
	}
	if *miningAddr == "" {
		fmt.Fprintln(os.Stderr, "ckb-deploy: -mining-addr is required")
		flag.Usage()
		os.Exit(2)
	}

	privKey, err := deployerKey(*keyFile, *coreConfig)
	if err != nil {
		fatal(err)
	}
	binaries, err := readContracts(*contractsDir)
	if err != nil {
		fatal(err)
	}

	deployer, err := ckb.NewDeployer(*rpcURL, *network, *sighashDep, *feeRate, privKey)
	if err != nil {
		fatal(err)
	}
	deployed, err := deployer.Deploy(context.Background(), contracts, binaries)
	if err != nil {
		fatal(err)
	}

	// Waited for, not merely sent. The very next thing anyone does with this
	// config is build a transaction whose cell deps point at these cells, and
	// CKB refuses a cell dep that is still sitting in the pool.
	//
	// To stderr, so that stdout stays nothing but config and can be appended
	// straight to core.toml.
	fmt.Fprintf(os.Stderr, "ckb-deploy: published %d scripts in %s, waiting for it to land\n",
		len(deployed), deployed[0].DepTxHash)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	block, err := deployer.AwaitCommitted(ctx, deployed[0].DepTxHash.String())
	if err != nil {
		fatal(err)
	}
	fmt.Fprintf(os.Stderr, "ckb-deploy: committed in L1 block %d\n", block)
	printConfig(*rpcURL, *network, *sighashDep, *miningAddr, *feeRate, deployed)
}

// deployerKey returns the key that pays for the deployment and owns the
// resulting code cells.
//
// Deriving it from a node config is for development, where the deployer and
// the miner are the same person and a devnet is rebuilt from scratch all day.
// A real deployment passes a key file: the code cells stay locked to whoever
// publishes them, and on a public network that lock is the only thing
// stopping somebody spending the cells out from under every node depending
// on them.
func deployerKey(keyFile, coreConfig string) ([]byte, error) {
	if keyFile != "" {
		return readKey(keyFile)
	}
	cfg, err := config.Load(coreConfig)
	if err != nil {
		return nil, err
	}
	_, privkey, err := keypair.GenKeyPairWithSecret(keypair.Secp256k1, []byte(cfg.Consensus.MinerSecret))
	if err != nil {
		return nil, fmt.Errorf("deriving the miner key: %w", err)
	}
	return privkey.Bytes(), nil
}

// readKey loads a hex private key, tolerating a 0x prefix and trailing
// whitespace from however the file was written.
func readKey(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading the key file: %w", err)
	}
	text := strings.TrimPrefix(strings.TrimSpace(string(raw)), "0x")
	key, err := hex.DecodeString(text)
	if err != nil {
		return nil, fmt.Errorf("the key file does not hold hex: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("the key file holds %d bytes, want 32", len(key))
	}
	return key, nil
}

// readContracts loads each compiled binary from where cargo leaves it.
func readContracts(dir string) (map[string][]byte, error) {
	out := make(map[string][]byte, len(contracts))
	for _, name := range contracts {
		path := filepath.Join(dir, name, "target", "riscv64imac-unknown-none-elf", "release", name)
		code, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("reading %s (build it first; see ckb/README.md): %w", path, err)
		}
		out[name] = code
	}
	return out, nil
}

// printConfig writes the `[ckb]` section describing what was just deployed.
//
// Only the code and the deps are printed. Every args among these scripts is
// derived by the node from the mining addr, because they form a chain — and
// writing them out here would be inviting somebody to edit one of them.
func printConfig(rpcURL, network, sighashDep, miningAddr string, feeRate uint64, deployed []ckb.Deployed) {
	fmt.Println("[ckb]")
	fmt.Println("enabled  = true")
	fmt.Printf("rpc_url  = %q\n", rpcURL)
	fmt.Printf("network  = %q\n", network)
	if network == "devnet" {
		fmt.Printf("sighash_dep_tx_hash = %q\n", sighashDep)
	}
	fmt.Printf("mining_addr = %q\n", miningAddr)
	fmt.Printf("fee_rate = %d\n", feeRate)

	for _, script := range deployed {
		fmt.Println()
		fmt.Printf("[ckb.%s]  # %s\n", tomlKey[script.Name], script.Name)
		fmt.Printf("code_hash   = %q\n", script.CodeHash.String())
		// data1 rather than type: the code hash is the hash of the binary, so
		// the script a node runs is fixed by the config it was given and
		// cannot be swapped underneath it.
		fmt.Println(`hash_type   = "data1"`)
		fmt.Printf("dep_tx_hash = %q\n", script.DepTxHash.String())
		fmt.Printf("dep_index   = %d\n", script.DepIndex)
		fmt.Println(`dep_type    = "code"`)
	}
}

// fatal reports a failure and stops; every error here happens before or
// during one transaction, so there is nothing half-done to clean up.
func fatal(err error) {
	fmt.Fprintln(os.Stderr, "ckb-deploy:", err)
	os.Exit(1)
}

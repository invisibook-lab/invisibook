package ckb

import (
	"bytes"
	"strings"
	"testing"

	"github.com/nervosnetwork/ckb-sdk-go/v2/address"
	ckbtypes "github.com/nervosnetwork/ckb-sdk-go/v2/types"
)

// The four scripts are parameterised in a chain, each by the hash of the one
// before it. This is the test that the chain is built in the right order and
// laid out the way the on-chain code reads it — get it wrong and the node
// writes cells under scripts that exist, on a chain nobody else is on.
func TestResolveDerivesScriptArgs(t *testing.T) {
	set := testSettings(t)

	miningAddr, err := address.Decode(testMiningAddr(t))
	if err != nil {
		t.Fatalf("decoding the test mining addr: %v", err)
	}
	wantMiningAddrHash := miningAddr.Script.Hash()
	if set.miningAddrLockHash != wantMiningAddrHash {
		t.Fatalf("mining addr lock hash is %s, want %s", set.miningAddrLockHash, wantMiningAddrHash)
	}

	// pob-spent recognises "back to the mining addr" by a lock hash in args.
	if !bytes.Equal(set.spentScript.Args, wantMiningAddrHash.Bytes()) {
		t.Fatalf("spent script args are %x, want the mining addr lock hash %s",
			set.spentScript.Args, wantMiningAddrHash)
	}
	// pob-vault tells a marked payout from its own change by the spent
	// script's hash, which only exists once the line above is settled.
	if set.spentTypeHash != set.spentScript.Hash() {
		t.Fatalf("spent type hash %s does not match the spent script it came from", set.spentTypeHash)
	}
	if !bytes.Equal(set.vaultScript.Args, set.spentTypeHash.Bytes()) {
		t.Fatalf("vault script args are %x, want the spent script hash %s",
			set.vaultScript.Args, set.spentTypeHash)
	}

	// pob-budget's parse_args reads three hashes in this order.
	want := make([]byte, 0, 3*ckbtypes.HashLength)
	want = append(want, set.miningAddrLockHash.Bytes()...)
	want = append(want, set.spentTypeHash.Bytes()...)
	want = append(want, set.sighashCodeHash.Bytes()...)
	if !bytes.Equal(set.budgetScript.Args, want) {
		t.Fatalf("budget script args are %x, want %x", set.budgetScript.Args, want)
	}
}

// A devnet's system scripts sit in that chain's own genesis transaction, so
// there is no value to guess at — and guessing would build transactions whose
// lock cannot be found.
func TestResolveRequiresDevnetSighashDep(t *testing.T) {
	cfg := &Config{
		Enabled:    true,
		Network:    "devnet",
		MiningAddr: testMiningAddr(t),
		Budget:     testScript(0x21),
		Commit:     testScript(0x22),
		Vault:      testScript(0x23),
		Spent:      testScript(0x24),
	}
	_, err := cfg.resolve()
	if err == nil {
		t.Fatal("resolved a devnet config with no sighash dep")
	}
	if !strings.Contains(err.Error(), "sighash_dep_tx_hash") {
		t.Fatalf("error does not name the missing field: %v", err)
	}
}

func TestResolveRejectsBadValues(t *testing.T) {
	base := func() *Config {
		return &Config{
			Enabled:          true,
			Network:          "devnet",
			SighashDepTxHash: hashOf(0x11),
			MiningAddr:       testMiningAddr(t),
			Budget:           testScript(0x21),
			Commit:           testScript(0x22),
			Vault:            testScript(0x23),
			Spent:            testScript(0x24),
		}
	}

	cases := map[string]func(*Config){
		"unknown network":  func(c *Config) { c.Network = "regtest" },
		"no mining addr":   func(c *Config) { c.MiningAddr = "" },
		"bad mining addr":  func(c *Config) { c.MiningAddr = "ckt1notanaddress" },
		"short code hash":  func(c *Config) { c.Commit.CodeHash = "0xdeadbeef" },
		"unknown hashtype": func(c *Config) { c.Budget.HashType = "type2" },
		"unknown deptype":  func(c *Config) { c.Vault.DepType = "group" },
	}
	for name, break_ := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := base()
			break_(cfg)
			if _, err := cfg.resolve(); err == nil {
				t.Fatal("resolved a config that names something undeployable")
			}
		})
	}
}

// A devnet shares the testnet's address format and system script code hashes;
// only the dep out point is its own. Treating it as anything else would
// produce addresses no devnet wallet recognises.
func TestDevnetRidesOnTestnet(t *testing.T) {
	set := testSettings(t)
	if set.network != ckbtypes.NetworkTest {
		t.Fatalf("devnet resolved to network %v, want the testnet's format", set.network)
	}
	wantDep := ckbtypes.HexToHash(hashOf(0x11))
	if set.sighashDep.OutPoint.TxHash != wantDep {
		t.Fatalf("sighash dep is %s, want the configured devnet genesis tx %s",
			set.sighashDep.OutPoint.TxHash, wantDep)
	}
	if set.sighashDep.DepType != ckbtypes.DepTypeDepGroup {
		t.Fatalf("sighash dep type is %s, want dep_group", set.sighashDep.DepType)
	}
}

package ckb

import (
	"context"
	"fmt"

	"github.com/nervosnetwork/ckb-sdk-go/v2/crypto/blake2b"
	"github.com/nervosnetwork/ckb-sdk-go/v2/crypto/secp256k1"
	"github.com/nervosnetwork/ckb-sdk-go/v2/rpc"
	ckbtypes "github.com/nervosnetwork/ckb-sdk-go/v2/types"
)

// Deployer publishes the PoB scripts to a CKB chain.
//
// It is a wallet and nothing more, because at deployment time nothing more
// exists: the four scripts are what this is about to create, so none of their
// code hashes, args or cell deps can be configured yet.
type Deployer struct {
	wallet
}

// NewDeployer returns a deployer for `network`, paying out of `privKey`.
//
// `sighashDepTxHash` is required on a devnet and ignored elsewhere, for the
// same reason it is in Config: the standard lock sits in that chain's own
// genesis transaction.
func NewDeployer(rpcURL, network, sighashDepTxHash string, feeRate uint64, privKey []byte) (*Deployer, error) {
	ckbNetwork, sighashDep, err := resolveNetwork(network, sighashDepTxHash)
	if err != nil {
		return nil, err
	}
	key, err := secp256k1.ToKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("ckb: loading the deployer key: %w", err)
	}
	client, err := rpc.Dial(rpcURL)
	if err != nil {
		return nil, fmt.Errorf("ckb: dialing %s: %w", rpcURL, err)
	}
	if feeRate == 0 {
		feeRate = DefaultConfig().FeeRate
	}
	return &Deployer{wallet: wallet{
		rpc:             client,
		key:             key,
		inflight:        newInFlight(),
		network:         ckbNetwork,
		feeRate:         feeRate,
		sighashDep:      sighashDep,
		sighashCodeHash: sighashCodeHashFor(ckbNetwork),
	}}, nil
}

// Deployed describes one published script: what a cell's type field has to
// say to run it, and where to find it.
type Deployed struct {
	// Name is the contract's directory name, e.g. "pob-budget".
	Name string
	// CodeHash identifies the script. Under `hash_type = "data1"` it is the
	// CKB hash of the binary itself.
	CodeHash ckbtypes.Hash
	// DepTxHash and DepIndex locate the cell holding the code.
	DepTxHash ckbtypes.Hash
	DepIndex  uint32
}

// Deploy publishes every binary in `contracts` as a code cell, in one
// transaction, and returns where each one landed.
//
// One transaction rather than four. The four scripts are one deployment —
// they are parameterised by each other's hashes and only make sense together
// — so publishing them atomically means a chain never holds half of them.
//
// The cells are locked to the deployer, which is deliberate: a code cell is
// capacity locked up for as long as anything depends on it, and the deployer
// should be able to reclaim it when a chain is torn down. On a public network
// that lock is also the one thing standing between a deployed script and
// whoever wants to spend the cell out from under every node depending on it.
//
// `contracts` maps a name to the compiled RISC-V binary; it must not be
// empty. Order is the caller's, and the returned indices follow it.
func (d *Deployer) Deploy(ctx context.Context, names []string, binaries map[string][]byte) ([]Deployed, error) {
	if len(names) == 0 {
		return nil, fmt.Errorf("nothing to deploy")
	}

	b, err := d.newBuilder(ctx)
	if err != nil {
		return nil, err
	}

	lock := d.minerLock()
	out := make([]Deployed, 0, len(names))
	for _, name := range names {
		code := binaries[name]
		if len(code) == 0 {
			return nil, fmt.Errorf("%s: the compiled binary is empty", name)
		}
		cell := &ckbtypes.CellOutput{Lock: lock}
		cell.Capacity = cell.OccupiedCapacity(code)

		// The index the cell will have. AddOutput appends, and the change
		// output was added first by newBuilder, so this is simply where it
		// goes — read back from the builder rather than counted here.
		idx := b.AddOutput(cell, code)
		out = append(out, Deployed{
			Name: name,
			// hash_type "data1" means the code hash is the hash of the code,
			// so it is known before the transaction is even sent — no type_id
			// cell, and no way for the script to be swapped later.
			CodeHash: bytesToHash(blake2b.Blake256(code)),
			DepIndex: uint32(idx),
		})
	}

	txHash, err := d.send(ctx, b)
	if err != nil {
		return nil, fmt.Errorf("publishing %d scripts: %w", len(names), err)
	}
	hash, err := parseHash(txHash)
	if err != nil {
		return nil, fmt.Errorf("the node returned an unreadable tx hash %q: %w", txHash, err)
	}
	for i := range out {
		out[i].DepTxHash = hash
	}
	return out, nil
}

// bytesToHash widens a 32-byte digest into CKB's hash type.
func bytesToHash(raw []byte) ckbtypes.Hash {
	var out ckbtypes.Hash
	copy(out[:], raw)
	return out
}

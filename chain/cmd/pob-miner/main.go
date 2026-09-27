// Command pob-miner does the two things a PoB miner has to do off the node:
// buy block space on CKB, and tell its own node what it bought.
//
//	pob-miner address              print the miner's CKB address and lock args
//	pob-miner prepay               create the budget cell, save the openings
//	pob-miner declare              post those openings to the node
//
// The split between the last two is not incidental. `prepay` puts *commitments*
// on L1 — a competitor reading the chain learns the miner's total and nothing
// about any single height — while the openings that turn them back into
// numbers stay here, in a local file, until the node needs them. Losing that
// file forfeits the prepayment: the money is spent and no height can be bid
// on with it, which is why `prepay` writes the file before broadcasting.
//
// Every subcommand reads the node's own config, so the key this derives is
// the key the node mines with (see consensus.Config.MinerSecret) and the
// scripts it builds cells under are the ones the node reads.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/nervosnetwork/ckb-sdk-go/v2/address"
	ckbtypes "github.com/nervosnetwork/ckb-sdk-go/v2/types"
	"github.com/yu-org/yu/common"
	"github.com/yu-org/yu/core/keypair"

	"github.com/invisibook-lab/invisibook/ckb"
	"github.com/invisibook-lab/invisibook/config"
	"github.com/invisibook-lab/invisibook/consensus"
	"github.com/invisibook-lab/invisibook/miner"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]

	var err error
	switch cmd {
	case "address":
		err = runAddress(args)
	case "prepay":
		err = runPrepay(args)
	case "declare":
		err = runDeclare(args)
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "pob-miner:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: pob-miner address|prepay|declare [flags]")
}

// runAddress prints where this miner's money has to be, and under which args
// its cells will be locked.
//
// The lock args are the useful half when standing up a devnet: they are what
// a dev chain spec's issued cells have to name for the miner to have anything
// to spend, and they are the same bytes V7 compares the block producer
// against.
func runAddress(argv []string) error {
	fs := flag.NewFlagSet("address", flag.ExitOnError)
	cfgPath := fs.String("core-config", "cfg/core.toml", "path to the node's core config")
	// Deliberately not taken from [ckb]: the address is wanted before that
	// section exists, while a devnet is still being funded.
	network := fs.String("network", "devnet", "mainnet, testnet or devnet")
	lockArgs := fs.String("lock-args", "",
		"encode these lock args instead of the miner's own; for addresses whose key lives elsewhere, such as the mining addr")
	if err := fs.Parse(argv); err != nil {
		return err
	}

	var (
		args   []byte
		pubkey keypair.PubKey
		err    error
	)
	if *lockArgs != "" {
		args, err = hex.DecodeString(strings.TrimPrefix(*lockArgs, "0x"))
		if err != nil {
			return fmt.Errorf("lock-args is not hex: %w", err)
		}
		if len(args) != 20 {
			return fmt.Errorf("lock-args is %d bytes, want 20", len(args))
		}
	} else {
		cfg, cfgErr := config.Load(*cfgPath)
		if cfgErr != nil {
			return cfgErr
		}
		pubkey, _, err = minerKey(cfg)
		if err != nil {
			return err
		}
		args, err = consensus.Blake160(pubkey.Bytes())
		if err != nil {
			return err
		}
	}

	net := ckbtypes.NetworkTest
	if *network == "mainnet" {
		net = ckbtypes.NetworkMain
	}
	addr, err := address.Address{
		Script: &ckbtypes.Script{
			CodeHash: ckbtypes.HexToHash("0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8"),
			HashType: ckbtypes.HashTypeType,
			Args:     args,
		},
		Network: net,
	}.Encode()
	if err != nil {
		return fmt.Errorf("encoding the miner address: %w", err)
	}

	if pubkey != nil {
		fmt.Printf("pubkey    %s\n", hex.EncodeToString(pubkey.Bytes()))
	}
	fmt.Printf("lock_args 0x%x\n", args)
	fmt.Printf("address   %s\n", addr)
	return nil
}

// runPrepay pays the mining addr and writes the allocation table, then saves
// the openings.
//
// The table is written once and can never be corrected (R3.1), which is what
// makes §7.3's ordering enforceable: a miner able to raise an allocation after
// seeing its own VRF output would have no reason to commit first. To bid on
// more heights later, prepay again — another budget cell, another table.
func runPrepay(argv []string) error {
	fs := flag.NewFlagSet("prepay", flag.ExitOnError)
	cfgPath := fs.String("core-config", "cfg/core.toml", "path to the node's core config")
	from := fs.Uint("from", 1, "first L2 height to bid on")
	count := fs.Uint("count", 50, "how many consecutive heights to bid on")
	amount := fs.String("amount", "10000000000", "shannon to allocate per height")
	out := fs.String("out", "schedule.json", "where to save the openings")
	if err := fs.Parse(argv); err != nil {
		return err
	}

	perHeight, ok := new(big.Int).SetString(*amount, 10)
	if !ok || perHeight.Sign() <= 0 {
		return fmt.Errorf("amount %q is not a positive decimal", *amount)
	}
	if *count == 0 {
		return fmt.Errorf("count must be at least 1")
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	client, err := newClient(cfg)
	if err != nil {
		return err
	}

	// The total has to equal what the table divides up (R3.2) — and equal the
	// capacity moved into the mining addr (R3.3), which CreateBudget handles.
	// R3.2 is not enforced anywhere yet, on chain or off; balancing it here is
	// what an honest miner does while that is still on trust.
	total := new(big.Int).Mul(perHeight, big.NewInt(int64(*count)))
	if !total.IsUint64() {
		return fmt.Errorf("a prepayment of %s shannon does not fit in a cell's capacity", total)
	}

	plan, err := miner.BuildPlan(miner.PlanRequest{
		Mode:  miner.ModeEven,
		From:  uint32(*from),
		Count: uint32(*count),
		Total: total,
	}, rand.Reader)
	if err != nil {
		return err
	}
	bids, entries, err := miner.Seal(plan, rand.Reader)
	if err != nil {
		return err
	}

	// Saved before the transaction goes out, for the same reason the node
	// stores a bid before submitting its commitment: a crash in between would
	// otherwise leave commitments on L1 that nobody can ever open, and the
	// capacity behind them spent for nothing.
	prepayment := &miner.Prepayment{Bids: bids}
	if err := miner.SavePrepayment(*out, prepayment); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	txHash, err := client.CreateBudget(ctx, total.Uint64(), entries)
	if err != nil {
		return err
	}
	prepayment.TxHash = txHash
	if err := miner.SavePrepayment(*out, prepayment); err != nil {
		return err
	}

	block, err := client.AwaitCommitted(ctx, txHash)
	if err != nil {
		return err
	}
	prepayment.L1Block = block
	if err := miner.SavePrepayment(*out, prepayment); err != nil {
		return err
	}

	fmt.Printf("prepaid %s shannon over heights %d..%d\n", total, *from, uint32(*from)+uint32(*count)-1)
	fmt.Printf("budget cell in %s\n", txHash)
	fmt.Printf("committed in L1 block %d; blocks spending it may not anchor before L1 block %d\n",
		block, block+consensus.PaymentLeadBlocks)
	fmt.Printf("openings saved to %s — losing this file forfeits the prepayment\n", *out)
	return nil
}

// runDeclare hands the openings to the node, which confirms each one against
// L1 before accepting it.
//
// Declaring is not paying. The money left for the mining addr when the budget
// cell was created; what travels here is the plaintext that opens a
// commitment already on L1, which is why the node can refuse a declaration
// outright — a miner claiming more than it committed to produces a different
// Poseidon hash.
func runDeclare(argv []string) error {
	fs := flag.NewFlagSet("declare", flag.ExitOnError)
	in := fs.String("in", "schedule.json", "the openings saved by prepay")
	node := fs.String("node", "http://127.0.0.1:8081", "the node's payment endpoint")
	from := fs.Uint("from", 0, "skip heights below this one; 0 declares everything")
	if err := fs.Parse(argv); err != nil {
		return err
	}

	plan, err := miner.LoadPrepayment(*in)
	if err != nil {
		return err
	}
	if plan.TxHash == "" {
		return fmt.Errorf("%s names no prepayment transaction; did prepay finish?", *in)
	}

	payments := make([]consensus.PaymentDeclaration, 0, len(plan.Bids))
	for _, b := range plan.Bids {
		if uint(b.Height) < *from {
			continue
		}
		payments = append(payments, consensus.PaymentDeclaration{
			BlockHeight: common.BlockNum(b.Height),
			Amount:      b.Amount,
			Random:      b.Random,
			TxHash:      plan.TxHash,
		})
	}
	if len(payments) == 0 {
		return fmt.Errorf("nothing left to declare at or above height %d", *from)
	}

	body, err := json.Marshal(consensus.PayL1TokenRequest{Payments: payments})
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Post(*node+"/pay_l1_token", "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("posting to %s: %w", *node, err)
	}
	defer resp.Body.Close()

	var answer consensus.PayL1TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&answer); err != nil {
		return fmt.Errorf("reading the node's answer: %w", err)
	}
	// Every rejection is printed, not just counted: each one names a height
	// this miner has already paid for and now cannot bid with.
	for _, r := range answer.Rejected {
		fmt.Fprintf(os.Stderr, "height %d rejected: %s\n", r.BlockHeight, r.Error)
	}
	if len(answer.Accepted) == 0 {
		return fmt.Errorf("the node accepted none of the %d declarations", len(payments))
	}
	fmt.Printf("declared %d of %d heights (%d..%d)\n",
		len(answer.Accepted), len(payments), answer.Accepted[0], answer.Accepted[len(answer.Accepted)-1])
	return nil
}

// minerKey derives the node's miner keypair from the seed in its config, so
// that cells this tool creates are owned by the key the node mines with.
func minerKey(cfg *config.Config) (keypair.PubKey, keypair.PrivKey, error) {
	pubkey, privkey, err := keypair.GenKeyPairWithSecret(keypair.Secp256k1, []byte(cfg.Consensus.MinerSecret))
	if err != nil {
		return nil, nil, fmt.Errorf("deriving the miner key: %w", err)
	}
	return pubkey, privkey, nil
}

// newClient connects to CKB using the node's own `[ckb]` section.
func newClient(cfg *config.Config) (*ckb.Client, error) {
	if !cfg.CKB.Enabled {
		return nil, fmt.Errorf("the [ckb] section is not enabled; run cmd/ckb-deploy first")
	}
	_, privkey, err := minerKey(cfg)
	if err != nil {
		return nil, err
	}
	return ckb.New(&cfg.CKB, privkey.Bytes())
}

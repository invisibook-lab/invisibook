package consensus

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"sync"

	"github.com/yu-org/yu/core/types"
)

// PaymentLeadBlocks is how far ahead of a block's own anchor its payment
// commitment must already have been written on L1 (whitepaper §7.3 and §9.3,
// ckb_layout.md V4).
//
// The gap is what makes selfish mining from L1 unprofitable. An attacker can
// post the same allocation on two competing L1 branches and wait to see which
// survives; requiring the allocation to be this far back means that by the
// time an L2 block spends it, the L1 branch carrying it has long since
// converged and no such window is open.
const PaymentLeadBlocks = 24

var (
	// ErrPaymentTooLate reports an allocation written too close to the block
	// that spends it.
	ErrPaymentTooLate = errors.New("the payment commitment was written too late")
	// ErrBudgetNotOwned reports a budget cell whose lock does not belong to
	// the block's producer.
	ErrBudgetNotOwned = errors.New("the budget cell does not belong to the block's producer")
)

// AnchoredHeader is an L2 header found in a submit cell on L1, with the
// height of the L1 block holding it.
type AnchoredHeader struct {
	// Header is the decoded L2 header, not yet verified.
	Header *types.Header
	// L1Height is the L1 block the submit cell was created in.
	L1Height uint64
}

// L1Reader reads back what PoB wrote to L1.
//
// Deliberately not a CKB client: nothing here mentions cells, scripts or
// transactions. The consensus code needs three facts out of L1 — which
// headers landed in a range of L1 blocks, how far L1 has got, and who owns an
// allocation table — and the rest belongs behind the implementation.
type L1Reader interface {
	// AnchoredIn returns every decodable header in submit cells created in
	// L1's canonical blocks `from` through `to`, inclusive. Cells that do not
	// decode are skipped: anyone can write one.
	AnchoredIn(ctx context.Context, from, to uint64) ([]*AnchoredHeader, error)

	// Tip returns the height of L1's canonical tip.
	Tip(ctx context.Context) (uint64, error)

	// BudgetOwner returns the lock args of the budget cell that `txHash`
	// created — the key that owns the allocation table inside it.
	//
	// CKB's standard lock carries the blake160 of a public key, not the key
	// itself, so this returns the args as they are and leaves the comparison
	// to the caller.
	BudgetOwner(ctx context.Context, txHash string) ([]byte, error)
}

// VerifyPaymentLead checks V4: that the allocation a block spends was written
// on L1 far enough ahead of the block's own anchor.
//
// Both arguments are L1 block heights: where the allocation entry was
// written, and where this block's header landed. R3.1 on chain only makes
// the allocation table immutable once written; that it was written early
// enough can only be checked here, off chain.
func VerifyPaymentLead(allocationHeight, anchorHeight uint64) error {
	if allocationHeight+PaymentLeadBlocks > anchorHeight {
		return fmt.Errorf("%w: allocation at L1 height %d, anchored at %d, needs a lead of %d",
			ErrPaymentTooLate, allocationHeight, anchorHeight, PaymentLeadBlocks)
	}
	return nil
}

// VerifyBudgetOwner checks the first item of V7: that the allocation table a
// block draws on belongs to the key that produced the block.
//
// This is the ground the rest of the payment check stands on, not an extra
// precaution. FetchAllocation is *told* which miner to look up, so a miner
// that names itself gets its own answer back — the commitment V3 compares
// against would be one the miner supplied. Only reading the cell's lock and
// holding it against the block's producer ties the two together.
//
// `minerPubkey` is the compressed secp256k1 key, as block.MinerPubkey carries
// it.
func VerifyBudgetOwner(ctx context.Context, reader L1Reader, txHash string, minerPubkey []byte) error {
	args, err := reader.BudgetOwner(ctx, txHash)
	if err != nil {
		return fmt.Errorf("reading the budget cell's owner: %w", err)
	}
	want, err := Blake160(minerPubkey)
	if err != nil {
		return err
	}
	if !bytes.Equal(args, want) {
		return fmt.Errorf("%w: the cell is locked to %x, the producer hashes to %x",
			ErrBudgetNotOwned, args, want)
	}
	return nil
}

// VerifyAnchoredHeader runs every check a header read off L1 needs before it
// may take part in fork choice, and returns its goal.
//
// The header arrives without its block, so this is everything that can be
// judged from the header alone: it is sealed by its producer (hash and
// signature), its VRF proof stands against its parent (V5), its payment opens
// an allocation on L1 bound to the producer (V3), the allocation table belongs
// to the producer (V7's first item), and that allocation was written far
// enough ahead of the anchor (V4). The transactions are bound later, through
// the transaction root, when the block itself is checked on arrival.
//
// `anchored` must carry a non-nil header.
func VerifyAnchoredHeader(
	ctx context.Context,
	reader L1Reader,
	verifier L1PaymentVerifier,
	anchored *AnchoredHeader,
) (*big.Int, error) {
	header := anchored.Header
	if err := VerifyHeaderSeal(header); err != nil {
		return nil, err
	}

	cdata, err := DecodeConsensusData(header.Extra)
	if err != nil {
		return nil, fmt.Errorf("header %s: decoding consensus data: %w", header.Hash, err)
	}
	if cdata.VRFResult == nil || len(cdata.VRFResult.Output) < vrfGoalBytes {
		return nil, fmt.Errorf("header %s carries no usable VRF output", header.Hash)
	}
	if !VRFVerify(header.MinerPubkey, header.PrevHash.Bytes(), cdata.VRFResult) {
		return nil, fmt.Errorf("header %s: VRF proof does not verify against its parent", header.Hash)
	}
	if cdata.L1Payment == nil {
		return nil, fmt.Errorf("header %s carries no payment", header.Hash)
	}

	// Ownership first: everything read out of that budget cell afterwards is
	// only worth what this check establishes.
	if err := VerifyBudgetOwner(ctx, reader, cdata.L1Payment.TxHash, header.MinerPubkey); err != nil {
		return nil, fmt.Errorf("header %s: %w", header.Hash, err)
	}
	alloc, err := ConfirmPayment(ctx, verifier, cdata.L1Payment,
		hex.EncodeToString(header.MinerPubkey), header.Height)
	if err != nil {
		return nil, fmt.Errorf("header %s: %w", header.Hash, err)
	}
	if err := VerifyPaymentLead(alloc.L1BlockNumber, anchored.L1Height); err != nil {
		return nil, fmt.Errorf("header %s: %w", header.Hash, err)
	}
	return CalcBlockScore(cdata.L1Payment.Amount, cdata.VRFResult.Output), nil
}

// MockL1Reader stands in for a CKB client in tests and in mock-L1 mode.
type MockL1Reader struct {
	mu sync.Mutex
	// anchored is every header recorded as landed on L1.
	anchored []*AnchoredHeader
	// tip is what Tip reports.
	tip uint64
	// owners maps a budget cell's creating transaction to its lock args.
	owners map[string][]byte
}

// Anchor records `header` as having landed in the L1 block at `l1Height`.
func (m *MockL1Reader) Anchor(header *types.Header, l1Height uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.anchored = append(m.anchored, &AnchoredHeader{Header: header, L1Height: l1Height})
}

// SetTip sets the L1 tip height the mock reports.
func (m *MockL1Reader) SetTip(tip uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tip = tip
}

// SetBudgetOwner records the lock args of the budget cell `txHash` created.
func (m *MockL1Reader) SetBudgetOwner(txHash string, args []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.owners == nil {
		m.owners = make(map[string][]byte)
	}
	m.owners[txHash] = append([]byte(nil), args...)
}

// AnchoredIn returns the recorded headers that landed in [from, to].
func (m *MockL1Reader) AnchoredIn(_ context.Context, from, to uint64) ([]*AnchoredHeader, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*AnchoredHeader
	for _, a := range m.anchored {
		if a.L1Height >= from && a.L1Height <= to {
			out = append(out, a)
		}
	}
	return out, nil
}

// Tip returns the recorded tip.
func (m *MockL1Reader) Tip(context.Context) (uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.tip, nil
}

// BudgetOwner returns the recorded lock args.
func (m *MockL1Reader) BudgetOwner(_ context.Context, txHash string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	args, ok := m.owners[txHash]
	if !ok {
		return nil, fmt.Errorf("%w: no budget cell in tx_hash=%s", ErrPaymentNotFound, txHash)
	}
	return append([]byte(nil), args...), nil
}

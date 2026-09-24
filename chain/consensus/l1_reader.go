package consensus

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"

	"github.com/yu-org/yu/common"
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
	// ErrNotOnChain reports an L1 block that is not on L1's canonical chain —
	// either it never was, or a reorg took it away. A commitment anchored
	// there counts for nothing.
	ErrNotOnChain = errors.New("the L1 block is not on L1's canonical chain")
	// ErrPaymentTooLate reports an allocation written too close to the block
	// that spends it.
	ErrPaymentTooLate = errors.New("the payment commitment was written too late")
	// ErrBudgetNotOwned reports a budget cell whose lock does not belong to
	// the block's producer.
	ErrBudgetNotOwned = errors.New("the budget cell does not belong to the block's producer")
)

// AnchoredCommitment is a block commitment as found on L1, together with the
// height of the L1 block holding it.
type AnchoredCommitment struct {
	// Commitment is the value the commit cell carries, hex-encoded.
	Commitment string
	// L1Height dates the anchoring. §8.2 rests on this number: a branch
	// bought after the fact can only carry commitments anchored recently, and
	// that is what distinguishes it from a branch that was really there at
	// the time.
	L1Height uint64
}

// L1Reader reads back what PoB wrote to L1.
//
// Deliberately not a CKB client: nothing here mentions cells, scripts or
// transactions. The consensus code needs three facts out of L1 — what a
// commitment says, when it was anchored, and who owns an allocation table —
// and the rest belongs behind the implementation, where a different L1 could
// answer the same questions differently.
type L1Reader interface {
	// CommitmentAt returns the commitment recorded at `loc`.
	//
	// It returns an error wrapping ErrNotOnChain when the block named by
	// loc.BlockHash is not on L1's canonical chain. This is why a reveal
	// names that block by hash and not by height: a height would still
	// resolve after a reorg replaced the block, and a commitment that went
	// away with it would appear to stand.
	CommitmentAt(ctx context.Context, loc *L1Location) (*AnchoredCommitment, error)

	// BudgetOwner returns the lock args of the budget cell that `txHash`
	// created — the key that owns the allocation table inside it.
	//
	// CKB's standard lock carries the blake160 of a public key, not the key
	// itself, so this returns the args as they are and leaves the comparison
	// to the caller.
	BudgetOwner(ctx context.Context, txHash string) ([]byte, error)
}

// VerifyAnchor checks V1: that the opening in `reveal` really opens a
// commitment sitting on L1 where the reveal says it is, and returns the
// height of the L1 block holding it.
//
// The height is the point of the exercise as much as the check is. It dates
// the block's anchoring, and V4 measures the payment against it.
//
// `reveal` must have passed Validate.
func VerifyAnchor(ctx context.Context, reader L1Reader, reveal *BlockReveal) (uint64, error) {
	if reveal == nil {
		return 0, errors.New("no reveal to verify")
	}

	anchored, err := reader.CommitmentAt(ctx, &L1Location{
		BlockHash: reveal.L1BlockHash,
		TxIdx:     reveal.TxIdx,
	})
	if err != nil {
		return 0, fmt.Errorf("reading the commitment for %s: %w", reveal.L2BlockHash, err)
	}

	// The reveal carries the block hash as text, the way Hash.String() wrote
	// it. A hash that does not parse decodes to the zero hash, which simply
	// commits to something else and fails the comparison below — no separate
	// guard needed.
	want, err := CommitBlockHash(common.HexToHash(reveal.L2BlockHash), reveal.Random)
	if err != nil {
		return 0, fmt.Errorf("recomputing the commitment for %s: %w", reveal.L2BlockHash, err)
	}
	if anchored.Commitment != want {
		return 0, fmt.Errorf("%w: L1 holds %s, the opening gives %s",
			ErrCommitmentMismatch, anchored.Commitment, want)
	}
	return anchored.L1Height, nil
}

// VerifyPaymentLead checks V4: that the allocation a block spends was written
// on L1 far enough ahead of the block's own anchor.
//
// Both arguments are L1 block heights: where the allocation entry was
// written, and where this block's commitment landed. R3.1 on chain only makes
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

// VerifyAgainstL1 runs the three checks a revealed block needs L1 for: V1
// (its commitment is anchored where the reveal says it is), V7's first item
// (the allocation table it draws on belongs to its producer) and V4 (that
// allocation was written far enough ahead of the anchor).
//
// They run together because they are not independent. V4 needs what V1
// returns — the height the commitment was anchored at — and V7's first item
// guards the very lookup V4's other half comes from: read the allocation
// before establishing who owns the table, and the number that comes back is
// one the producer chose. Run apart, each would also read L1 again for what
// the previous one already knew.
//
// `block` must carry decodable consensus data, and `reveal` must be the
// opening for that block.
func VerifyAgainstL1(
	ctx context.Context,
	reader L1Reader,
	verifier L1PaymentVerifier,
	block *types.Block,
	reveal *BlockReveal,
) error {
	if block == nil || block.Header == nil {
		return errors.New("block has no header")
	}

	anchorHeight, err := VerifyAnchor(ctx, reader, reveal)
	if err != nil {
		return err
	}

	cdata, err := DecodeConsensusData(block.Extra)
	if err != nil {
		return fmt.Errorf("block %s: decoding consensus data: %w", block.Hash, err)
	}
	if cdata.L1Payment == nil {
		return fmt.Errorf("block %s carries no payment", block.Hash)
	}
	txHash := cdata.L1Payment.TxHash

	// Ownership first: everything read out of that budget cell afterwards is
	// only worth what this check establishes.
	if err := VerifyBudgetOwner(ctx, reader, txHash, block.MinerPubkey); err != nil {
		return fmt.Errorf("block %s: %w", block.Hash, err)
	}

	alloc, err := verifier.FetchAllocation(ctx, txHash,
		hex.EncodeToString(block.MinerPubkey), block.Height)
	if err != nil {
		return fmt.Errorf("block %s: reading its allocation: %w", block.Hash, err)
	}
	if err := VerifyPaymentLead(alloc.L1BlockNumber, anchorHeight); err != nil {
		return fmt.Errorf("block %s: %w", block.Hash, err)
	}
	return nil
}

// MockL1Reader stands in for a CKB client until one exists.
type MockL1Reader struct {
	mu sync.Mutex
	// anchored maps a spot on L1 to what was recorded there.
	anchored map[string]*AnchoredCommitment
	// orphaned holds L1 block hashes treated as no longer canonical — how a
	// test reproduces a reorg carrying a commitment away.
	orphaned map[string]bool
	// owners maps a budget cell's creating transaction to its lock args.
	owners map[string][]byte
}

// locationKey identifies one spot on L1.
func locationKey(loc *L1Location) string {
	return fmt.Sprintf("%s/%d", loc.BlockHash, loc.TxIdx)
}

// Anchor records a commitment at a location, standing in for a submission
// that made it into the L1 block at `l1Height`.
func (m *MockL1Reader) Anchor(loc *L1Location, commitment string, l1Height uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.anchored == nil {
		m.anchored = make(map[string]*AnchoredCommitment)
	}
	m.anchored[locationKey(loc)] = &AnchoredCommitment{Commitment: commitment, L1Height: l1Height}
}

// Orphan marks an L1 block as no longer on the canonical chain.
func (m *MockL1Reader) Orphan(blockHash string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.orphaned == nil {
		m.orphaned = make(map[string]bool)
	}
	m.orphaned[blockHash] = true
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

// CommitmentAt returns what was recorded at `loc`.
func (m *MockL1Reader) CommitmentAt(_ context.Context, loc *L1Location) (*AnchoredCommitment, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.orphaned[loc.BlockHash] {
		return nil, fmt.Errorf("%w: %s", ErrNotOnChain, loc.BlockHash)
	}
	anchored, ok := m.anchored[locationKey(loc)]
	if !ok {
		return nil, fmt.Errorf("%w: nothing recorded at %s", ErrPaymentNotFound, locationKey(loc))
	}
	// Copied, so a caller cannot reach back into the mock's own table.
	copied := *anchored
	return &copied, nil
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

package ckb

import (
	"context"
	"encoding/binary"
	"fmt"
	"math/big"

	ckbtypes "github.com/nervosnetwork/ckb-sdk-go/v2/types"

	"github.com/invisibook-lab/invisibook/consensus"
)

// Allocate turns one plaintext bid into the table row that reaches L1.
//
// `amount` is what this miner is willing to spend on `height`, in shannon;
// `randomHex` is the 64-character blinding factor that opens the commitment
// later (consensus.NewPaymentRandomHex). The caller must keep both: the L2 network is shown the opening when
// the block is revealed, and an opening that is lost makes the allocation
// unusable — the money is spent and the height cannot be bid on with it.
func Allocate(height uint32, amount *big.Int, randomHex string) (BudgetEntry, error) {
	commitment, err := consensus.PaymentCommit(amount, randomHex)
	if err != nil {
		return BudgetEntry{}, fmt.Errorf("committing to the allocation for height %d: %w", height, err)
	}
	return BudgetEntry{Height: height, Commitment: commitment}, nil
}

// CreateBudget pays `prepaid` shannon into the mining addr and writes the
// allocation table dividing it among L2 heights, both in one transaction.
//
// One transaction because R3.3 demands it: the budget cell's declared total
// has to equal the capacity this same transaction moves into the mining addr,
// or a miner could claim to have paid whatever it liked. The script sums the
// two sides and refuses the mismatch.
//
// The table must also add up to that total (R3.2). `proof` is the
// zero-knowledge proof that it does (budgetproof.Prove over the same
// openings); it travels in the witnesses from the budget cell's own output
// index on (see proofWitnesses), where the script looks for it. Without a
// proof that verifies against `prepaid` and exactly these commitments, in
// this order, the cell cannot be created.
//
// The table is written once and can never be corrected (R3.1), which is what
// makes §7.3's ordering enforceable — a miner that could raise an allocation
// after seeing its own VRF output would have no reason to commit first. To
// add budget a miner creates another budget cell, with its own balanced
// table.
//
// `allocations` must be ascending by height with no height twice.
func (c *Client) CreateBudget(ctx context.Context, prepaid uint64, allocations []BudgetEntry, proof []byte) (string, error) {
	if len(proof) == 0 {
		return "", fmt.Errorf("the allocation table carries no balance proof")
	}
	data, err := (&BudgetData{Prepaid: prepaid, Allocations: allocations}).Encode()
	if err != nil {
		return "", err
	}

	// The prepayment carries the vault script, not just the mining addr's
	// lock. R3.3 looks only at the lock, but a cell that arrives under that
	// lock without the vault script on it is capacity the operator could
	// later spend with no mark attached — R4.0 governs cells the vault
	// script guards, and this is how one comes to be guarded (§4).
	payment := &ckbtypes.CellOutput{
		Capacity: prepaid,
		Lock:     c.set.miningAddrLock,
		Type:     c.set.vaultScript,
	}
	if floor := payment.OccupiedCapacity(nil); prepaid < floor {
		return "", fmt.Errorf("a prepayment of %d shannon cannot occupy its own cell, which needs %d",
			prepaid, floor)
	}

	// The budget cell holds only the table. The money is in the mining addr
	// and is gone; this cell's capacity is the storage deposit, which comes
	// back when the miner spends the cell at the end of the period (R3.1).
	budget := &ckbtypes.CellOutput{Lock: c.minerLock(), Type: c.set.budgetScript}
	budget.Capacity = budget.OccupiedCapacity(data)

	b, err := c.newBuilder(ctx)
	if err != nil {
		return "", err
	}
	b.AddOutput(payment, nil)
	budgetIndex := b.AddOutput(budget, data)
	// The proof has to be in place before Build, which prices the
	// transaction by its size: added afterwards, ~100 KB would go unpaid.
	// Build only appends one witness per input it draws, so the slots from
	// the budget cell's index on are made here; the sighash handler later
	// writes its placeholder into slot 0 without disturbing these.
	chunks := proofWitnesses(proof)
	for len(b.Witnesses) < budgetIndex+len(chunks) {
		b.Witnesses = append(b.Witnesses, []byte{})
	}
	for i, chunk := range chunks {
		if err := b.SetWitness(uint(budgetIndex+i), ckbtypes.WitnessTypeOutputType, chunk); err != nil {
			return "", fmt.Errorf("attaching the balance proof: %w", err)
		}
	}
	b.AddCellDep(c.set.vaultDep)
	b.AddCellDep(c.set.budgetDep)

	txHash, err := c.send(ctx, b)
	if err != nil {
		return "", fmt.Errorf("prepaying %d shannon over %d heights: %w", prepaid, len(allocations), err)
	}
	return txHash, nil
}

// maxWitnessSize is the largest witness the standard sighash lock accepts: it
// reads every witness it signs over — each of its own group's, and every one
// past the inputs — into a 32 KB buffer, and fails with -22 on anything
// bigger.
const maxWitnessSize = 32 * 1024

// proofChunkPayload is how much proof one witness carries: maxWitnessSize
// less the WitnessArgs envelope, with room to spare.
const proofChunkPayload = maxWitnessSize - 64

// proofWitnesses cuts a balance proof into the chunks that go, one per
// witness, into WitnessArgs.output_type from the budget cell's index on: the
// total length as a little-endian u32, then the proof, split every
// proofChunkPayload bytes. A ~110 KB proof in one witness would be refused by
// the miner's own lock. This is budget_stark::witness::split; the script
// reassembles it with budget_stark::witness::join.
func proofWitnesses(proof []byte) [][]byte {
	prefixed := make([]byte, 4, 4+len(proof))
	binary.LittleEndian.PutUint32(prefixed, uint32(len(proof)))
	prefixed = append(prefixed, proof...)

	var chunks [][]byte
	for len(prefixed) > proofChunkPayload {
		chunks = append(chunks, prefixed[:proofChunkPayload])
		prefixed = prefixed[proofChunkPayload:]
	}
	return append(chunks, prefixed)
}

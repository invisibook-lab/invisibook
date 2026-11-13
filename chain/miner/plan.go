package miner

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"math/big"
	"sort"

	"github.com/invisibook-lab/invisibook/budgetproof"
	"github.com/invisibook-lab/invisibook/ckb"
	"github.com/invisibook-lab/invisibook/consensus"
)

// Mode is how a prepayment is divided among L2 heights.
type Mode string

const (
	// ModeEven gives every height the same share.
	ModeEven Mode = "even"
	// ModeRandom scatters shares around the mean, so a rival watching the
	// miner win cannot infer one flat bid to sit just above.
	ModeRandom Mode = "random"
	// ModeManual takes the miner's own table as given.
	ModeManual Mode = "manual"
)

const (
	// MaxAllocations bounds how many heights one prepayment may cover: the
	// most one balance proof covers (lib/budget-stark's MAX_ENTRIES).
	MaxAllocations = 1024
	// DefaultSpreadBps is how far a random share may stray from the mean when
	// the caller does not say: ±50%.
	DefaultSpreadBps = 5000
	// maxSpreadBps keeps every random weight positive.
	maxSpreadBps = 9999
	// bpsBase is 100% in basis points.
	bpsBase = 10000
)

// Allocation is what the miner is willing to spend on one L2 height.
type Allocation struct {
	// Height is the L2 block height this allocation competes for.
	Height uint32
	// Amount is the allocation in shannon; always positive.
	Amount *big.Int
}

// PlanRequest describes a prepayment to divide up.
type PlanRequest struct {
	Mode Mode
	// From is the first L2 height; Count is how many consecutive heights.
	// Used by ModeEven and ModeRandom.
	From  uint32
	Count uint32
	// Total is the prepayment in shannon, divided exactly among the heights.
	// Used by ModeEven and ModeRandom.
	Total *big.Int
	// SpreadBps is, for ModeRandom, how far a share may stray from the mean
	// in basis points; zero means DefaultSpreadBps.
	SpreadBps uint32
	// Manual is the miner's own table, for ModeManual.
	Manual []Allocation
}

// BuildPlan divides a prepayment among L2 heights, returning the table
// ascending by height. The amounts always sum to exactly the total the caller
// gave (or, in ModeManual, to the sum of the table): the budget cell is
// balanced by equality (R3.2), so a rounding remainder cannot be left over.
// `rnd` is the randomness source ModeRandom draws from; crypto/rand in
// production.
func BuildPlan(req PlanRequest, rnd io.Reader) ([]Allocation, error) {
	switch req.Mode {
	case ModeManual:
		return manualPlan(req.Manual)
	case ModeEven, ModeRandom:
		if err := checkRange(req.From, req.Count); err != nil {
			return nil, err
		}
		if req.Total == nil || req.Total.Sign() <= 0 {
			return nil, fmt.Errorf("total must be positive")
		}
		if req.Total.Cmp(big.NewInt(int64(req.Count))) < 0 {
			return nil, fmt.Errorf("total of %s shannon cannot give each of %d heights at least 1 shannon",
				req.Total, req.Count)
		}
		if req.Total.Cmp(new(big.Int).SetUint64(math.MaxUint64)) > 0 {
			return nil, fmt.Errorf("total of %s shannon does not fit in a cell's capacity", req.Total)
		}
		weights, err := shareWeights(req, rnd)
		if err != nil {
			return nil, err
		}
		return divide(req.From, req.Total, weights)
	default:
		return nil, fmt.Errorf("mode %q is not one of even, random, manual", req.Mode)
	}
}

// checkRange rejects an empty or oversized run of heights, or one that runs
// past the end of the height space.
func checkRange(from, count uint32) error {
	if count == 0 {
		return fmt.Errorf("count must be at least 1")
	}
	if count > MaxAllocations {
		return fmt.Errorf("count %d exceeds the limit of %d heights per prepayment", count, MaxAllocations)
	}
	if from == 0 {
		return fmt.Errorf("from must be at least 1: height 0 is the genesis block")
	}
	if uint64(from)+uint64(count) > math.MaxUint32 {
		return fmt.Errorf("heights %d..+%d run past the end of the height space", from, count)
	}
	return nil
}

// shareWeights returns one relative weight per height: equal for ModeEven,
// scattered within the requested spread for ModeRandom.
func shareWeights(req PlanRequest, rnd io.Reader) ([]*big.Int, error) {
	weights := make([]*big.Int, req.Count)
	var spread int64
	if req.Mode == ModeRandom {
		spread = int64(req.SpreadBps)
		if spread == 0 {
			spread = DefaultSpreadBps
		}
		if spread > maxSpreadBps {
			return nil, fmt.Errorf("spread of %d bps is out of range; the most is %d", req.SpreadBps, maxSpreadBps)
		}
	}
	for i := range weights {
		weights[i] = big.NewInt(bpsBase)
		if req.Mode != ModeRandom {
			continue
		}
		// Uniform in [10000-spread, 10000+spread].
		offset, err := rand.Int(rnd, big.NewInt(2*spread+1))
		if err != nil {
			return nil, fmt.Errorf("drawing a random share: %w", err)
		}
		weights[i].Add(big.NewInt(bpsBase-spread), offset)
	}
	return weights, nil
}

// divide splits `total` in proportion to `weights` starting at height `from`.
// Every share is floored, then the leftover — fewer shannon than there are
// heights — goes one each to the first heights, so the sum is exact.
func divide(from uint32, total *big.Int, weights []*big.Int) ([]Allocation, error) {
	weightSum := new(big.Int)
	for _, w := range weights {
		weightSum.Add(weightSum, w)
	}

	plan := make([]Allocation, len(weights))
	assigned := new(big.Int)
	for i, w := range weights {
		share := new(big.Int).Mul(total, w)
		share.Quo(share, weightSum)
		plan[i] = Allocation{Height: from + uint32(i), Amount: share}
		assigned.Add(assigned, share)
	}
	leftover := new(big.Int).Sub(total, assigned).Int64()
	for i := int64(0); i < leftover; i++ {
		plan[i].Amount.Add(plan[i].Amount, big.NewInt(1))
	}

	for _, a := range plan {
		if a.Amount.Sign() <= 0 {
			return nil, fmt.Errorf("total of %s shannon is too small to give height %d a positive share",
				total, a.Height)
		}
	}
	return plan, nil
}

// manualPlan validates a miner-supplied table and returns it ascending by
// height. Every amount must be positive and no height may repeat.
func manualPlan(table []Allocation) ([]Allocation, error) {
	if len(table) == 0 {
		return nil, fmt.Errorf("allocations must not be empty")
	}
	if len(table) > MaxAllocations {
		return nil, fmt.Errorf("%d allocations exceed the limit of %d heights per prepayment",
			len(table), MaxAllocations)
	}
	plan := make([]Allocation, len(table))
	copy(plan, table)
	sort.Slice(plan, func(i, j int) bool { return plan[i].Height < plan[j].Height })

	total := new(big.Int)
	for i, a := range plan {
		if a.Height == 0 {
			return nil, fmt.Errorf("height 0 is the genesis block")
		}
		if a.Amount == nil || a.Amount.Sign() <= 0 {
			return nil, fmt.Errorf("height %d needs a positive amount", a.Height)
		}
		if i > 0 && plan[i-1].Height == a.Height {
			return nil, fmt.Errorf("height %d appears twice", a.Height)
		}
		total.Add(total, a.Amount)
	}
	if total.Cmp(new(big.Int).SetUint64(math.MaxUint64)) > 0 {
		return nil, fmt.Errorf("total of %s shannon does not fit in a cell's capacity", total)
	}
	return plan, nil
}

// BlindingFactor draws 32 fresh random bytes, hex encoded. The console cuts
// prepayment IDs from it; blinding factors for commitments come from
// consensus.NewPaymentRandomHex, which additionally keeps every word inside
// the commitment's field.
func BlindingFactor(rnd io.Reader) (string, error) {
	raw := make([]byte, 32)
	if _, err := io.ReadFull(rnd, raw); err != nil {
		return "", fmt.Errorf("drawing random bytes: %w", err)
	}
	return hex.EncodeToString(raw), nil
}

// Prover proves that a table of amounts under the given blinding factors
// balances (R3.2). budgetproof.Prove is the real one.
type Prover func(amounts []uint64, randoms []string) (*budgetproof.Proof, error)

// Seal turns a plan into what has to be kept and what goes to L1: the bids,
// each holding its amount and a fresh blinding factor, the table of
// commitments to them, and the proof that the table adds up to the plan's
// total. The caller must persist the bids before sending the entries
// anywhere: an opening that is lost makes its allocation unusable.
func Seal(plan []Allocation, rnd io.Reader, prove Prover) ([]Bid, []ckb.BudgetEntry, []byte, error) {
	bids := make([]Bid, len(plan))
	entries := make([]ckb.BudgetEntry, len(plan))
	amounts := make([]uint64, len(plan))
	randoms := make([]string, len(plan))
	for i, a := range plan {
		if a.Amount == nil || a.Amount.Sign() < 0 || !a.Amount.IsUint64() {
			return nil, nil, nil, fmt.Errorf("height %d: amount %v is not a u64", a.Height, a.Amount)
		}
		random, err := consensus.NewPaymentRandomHex(rnd)
		if err != nil {
			return nil, nil, nil, err
		}
		entry, err := ckb.Allocate(a.Height, a.Amount, random)
		if err != nil {
			return nil, nil, nil, err
		}
		entries[i] = entry
		bids[i] = Bid{Height: a.Height, Amount: a.Amount.String(), Random: random}
		amounts[i] = a.Amount.Uint64()
		randoms[i] = random
	}

	proof, err := prove(amounts, randoms)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("proving the table balances: %w", err)
	}
	// The table on L1 holds this package's commitments and the proof is over
	// the prover's. L1 would refuse a mismatch, but only after the miner had
	// paid the fee; comparing here costs nothing.
	for i, c := range proof.Commitments {
		if c != entries[i].Commitment {
			return nil, nil, nil, fmt.Errorf("height %d: the prover committed to %s, the table holds %s",
				entries[i].Height, c, entries[i].Commitment)
		}
	}
	return bids, entries, proof.Bytes, nil
}

// PlanTotal is the sum of a plan's amounts, in shannon.
func PlanTotal(plan []Allocation) *big.Int {
	total := new(big.Int)
	for _, a := range plan {
		total.Add(total, a.Amount)
	}
	return total
}

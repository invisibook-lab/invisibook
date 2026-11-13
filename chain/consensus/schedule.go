package consensus

import (
	"errors"

	"github.com/yu-org/yu/common"
)

// AnchorSchedule maps batches of L2 heights to the L1 windows their headers
// must land in.
//
// L2 genesis corresponds to L1 height n. Heights are grouped b at a time:
// batch i is [i*b+1, i*b+b]. Its headers count only when they land in L1
// blocks [n+i, n+i+k] — windows overlap, one opening per L1 block. Because
// the window is known in advance, a node scans exactly those k+1 L1 blocks
// for a batch and keeps nothing once the batch is decided.
//
// k is a chain-quality parameter: any k consecutive L1 blocks include one
// from an honest producer, who packs the batch's headers. That is why a
// window that closes holding no complete batch is not provided for.
type AnchorSchedule struct {
	// GenesisL1Height is n.
	GenesisL1Height uint64
	// BatchSize is b; must be positive.
	BatchSize uint64
	// Window is k.
	Window uint64
	// ConfirmDepth is how far L1 must be past a window's end before the
	// batch is decided, so an L1 reorg cannot change what the window held.
	ConfirmDepth uint64
}

// NewAnchorSchedule reads the schedule out of `cfg`. n is the same value the
// genesis block carries, which checkGenesis holds the stored chain to. It
// refuses a zero batch size, which would put every height in one batch.
func NewAnchorSchedule(cfg *Config) (AnchorSchedule, error) {
	if cfg.AnchorBatchSize == 0 {
		return AnchorSchedule{}, errors.New("anchor_batch_size must be positive")
	}
	return AnchorSchedule{
		GenesisL1Height: cfg.AnchorGenesisL1Height,
		BatchSize:       cfg.AnchorBatchSize,
		Window:          cfg.AnchorWindow,
		ConfirmDepth:    cfg.AnchorConfirmDepth,
	}, nil
}

// BatchOf returns the batch holding L2 height `height`, which must be at
// least 1 (genesis is in no batch).
func (s AnchorSchedule) BatchOf(height common.BlockNum) uint64 {
	return (uint64(height) - 1) / s.BatchSize
}

// FirstHeight returns the lowest L2 height of batch `batch`.
func (s AnchorSchedule) FirstHeight(batch uint64) common.BlockNum {
	return common.BlockNum(batch*s.BatchSize + 1)
}

// WindowOf returns the inclusive L1 height range batch `batch`'s headers must
// land in.
func (s AnchorSchedule) WindowOf(batch uint64) (from, to uint64) {
	from = s.GenesisL1Height + batch
	return from, from + s.Window
}

// Decidable reports whether batch `batch` can be decided with L1 at `l1Tip`:
// its window has closed and been buried ConfirmDepth blocks deep.
func (s AnchorSchedule) Decidable(batch, l1Tip uint64) bool {
	_, to := s.WindowOf(batch)
	return l1Tip >= to+s.ConfirmDepth
}

// WindowOpen reports whether a header of batch `batch` submitted now, with
// L1 at `l1Tip`, would land inside or after the window's start. Submitting
// earlier would land before n+batch, where no node looks.
func (s AnchorSchedule) WindowOpen(batch, l1Tip uint64) bool {
	from, _ := s.WindowOf(batch)
	return l1Tip+1 >= from
}

// WindowClosed reports whether a header of batch `batch` submitted now, with
// L1 at `l1Tip`, could no longer land inside the window.
func (s AnchorSchedule) WindowClosed(batch, l1Tip uint64) bool {
	_, to := s.WindowOf(batch)
	return l1Tip >= to
}

package miner

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// PrepayStatus is where a prepayment is in its life.
type PrepayStatus string

const (
	// StatusBroadcasting means the openings are saved and the L1 transaction
	// is being built and sent.
	StatusBroadcasting PrepayStatus = "broadcasting"
	// StatusConfirming means L1 has the transaction in its pool and it is
	// waiting to be committed to a block.
	StatusConfirming PrepayStatus = "confirming"
	// StatusConfirmed means the budget cell is committed on L1; its
	// allocations can now be declared.
	StatusConfirmed PrepayStatus = "confirmed"
	// StatusFailed means nothing was spent: the transaction never went out.
	StatusFailed PrepayStatus = "failed"
	// StatusUnconfirmed means the transaction was sent but L1 has not
	// committed it. The money may or may not be gone; the hash is kept so the
	// miner can check.
	StatusUnconfirmed PrepayStatus = "unconfirmed"
	// StatusInterrupted means the node stopped between saving the openings and
	// learning the transaction's hash, so whether anything was sent is unknown.
	StatusInterrupted PrepayStatus = "interrupted"
)

// Bid is one height's opening: the amount committed and the blinding factor
// that opens the commitment on L1.
type Bid struct {
	Height uint32 `json:"height"`
	// Amount is the allocation in shannon, as a decimal string.
	Amount string `json:"amount"`
	// Random is the 64-char hex blinding factor. It is a secret: the
	// commitment is only as hidden as this stays.
	Random string `json:"random"`
	// Declared is set once the node has accepted this opening.
	Declared bool `json:"declared,omitempty"`
}

// Prepayment is one budget cell: its total, its allocation table with the
// openings, and how far along it is on L1.
type Prepayment struct {
	ID        string       `json:"id,omitempty"`
	CreatedAt time.Time    `json:"created_at,omitempty"`
	Status    PrepayStatus `json:"status,omitempty"`
	// Error explains a Failed or Unconfirmed status.
	Error string `json:"error,omitempty"`
	// Total is the prepaid amount in shannon, as a decimal string.
	Total string `json:"total,omitempty"`
	// TxHash is the L1 transaction that created the budget cell.
	TxHash string `json:"tx_hash"`
	// L1Block is the block that transaction was committed in. A block may only
	// spend an allocation that predates its own anchoring by
	// consensus.PaymentLeadBlocks, measured from here.
	L1Block uint64 `json:"l1_block"`
	// AutoDeclare asks for the openings to be declared as soon as the budget
	// cell is committed.
	AutoDeclare bool  `json:"auto_declare,omitempty"`
	Bids        []Bid `json:"bids"`
}

// Store keeps prepayments on disk. Openings are worth exactly as much as the
// prepayment behind them, so every change is written out before the caller
// carries on, and the file is readable by its owner alone.
type Store struct {
	mu    sync.Mutex
	path  string
	items []*Prepayment
}

// OpenStore loads the prepayments at `path`, or starts empty when the file
// does not exist yet.
func OpenStore(path string) (*Store, error) {
	s := &Store{path: path}
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading prepayments: %w", err)
	}
	if err := json.Unmarshal(raw, &s.items); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	return s, nil
}

// Add records a new prepayment and persists it.
func (s *Store) Add(p *Prepayment) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items = append(s.items, p)
	return s.saveLocked()
}

// Update applies `change` to the prepayment named `id` and persists the
// result. It returns the updated prepayment, or an error when there is none.
func (s *Store) Update(id string, change func(*Prepayment)) (Prepayment, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, p := range s.items {
		if p.ID == id {
			change(p)
			return clonePrepayment(p), s.saveLocked()
		}
	}
	return Prepayment{}, fmt.Errorf("no prepayment %q", id)
}

// Get returns a copy of the prepayment named `id`.
func (s *Store) Get(id string) (Prepayment, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, p := range s.items {
		if p.ID == id {
			return clonePrepayment(p), true
		}
	}
	return Prepayment{}, false
}

// List returns copies of every prepayment, oldest first.
func (s *Store) List() []Prepayment {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Prepayment, len(s.items))
	for i, p := range s.items {
		out[i] = clonePrepayment(p)
	}
	return out
}

// HeightTaken reports whether a live prepayment already allocates `height`.
// A failed prepayment spent nothing, so its heights are free again.
func (s *Store) HeightTaken(height uint32) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, p := range s.items {
		if p.Status == StatusFailed {
			continue
		}
		for _, b := range p.Bids {
			if b.Height == height {
				return true
			}
		}
	}
	return false
}

// LastHeight is the highest height any live prepayment allocates, or zero
// when there is none. A failed prepayment spent nothing and does not count.
func (s *Store) LastHeight() uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	var last uint32
	for _, p := range s.items {
		if p.Status == StatusFailed {
			continue
		}
		for _, b := range p.Bids {
			if b.Height > last {
				last = b.Height
			}
		}
	}
	return last
}

// saveLocked writes the whole file. `s.mu` must be held.
func (s *Store) saveLocked() error {
	return writeJSON(s.path, s.items)
}

// clonePrepayment copies a prepayment so callers cannot race the store's own
// copy through the shared bid slice.
func clonePrepayment(p *Prepayment) Prepayment {
	c := *p
	c.Bids = append([]Bid(nil), p.Bids...)
	return c
}

// SavePrepayment writes a single prepayment as a standalone file, which is how
// `pob-miner prepay` hands its openings to `pob-miner declare`.
func SavePrepayment(path string, p *Prepayment) error {
	return writeJSON(path, p)
}

// LoadPrepayment reads a file written by SavePrepayment.
func LoadPrepayment(path string) (*Prepayment, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading the openings: %w", err)
	}
	var p Prepayment
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	return &p, nil
}

// writeJSON replaces `path` with the JSON of `v`, owner-readable only.
//
// Written to a sibling and renamed into place, so a crash mid-write leaves the
// previous file rather than half of a new one: this file is the only copy of
// the openings.
func writeJSON(path string, v any) error {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("creating %s: %w", dir, err)
		}
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return fmt.Errorf("saving the openings to %s: %w", path, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("saving the openings to %s: %w", path, err)
	}
	return nil
}

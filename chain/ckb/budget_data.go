// Package ckb is the CKB client sitting behind the three L1 interfaces the
// Proof-of-Buy consensus reaches L1 through: it reads back anchored
// commitments and allocation tables, posts block commitments, and builds the
// budget cell a miner prepays with.
//
// The split from `consensus` is deliberate. Nothing in `consensus` mentions
// cells, scripts or out points — it asks L1 three questions and gets three
// answers — so a different L1 could answer them differently without that
// package changing. Everything CKB-shaped lives here.
package ckb

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

// Lengths of the pieces a budget cell's data is built from.
//
// `prepaidLen` is fixed by the on-chain script: pob-budget reads the total
// out of the first 8 bytes of the cell data as a little-endian u64 (R3.3),
// which is why the total sits in front of the molecule table rather than
// inside it. A molecule table would put its own size and offset header there
// and the script would read that instead.
const (
	prepaidLen      = 8
	heightLen       = 4
	commitmentLen   = 32
	allocationLen   = heightLen + commitmentLen
	fixvecHeaderLen = 4
)

// BudgetEntry is one row of a miner's allocation table: what it committed to
// bidding at one L2 height.
//
// The amount itself is not here and never reaches L1. Only the Poseidon
// commitment to `(amount, random)` does, so that a rival cannot read how much
// this miner is spending at a given height and bid just above it —
// proof_of_buy.md §7.2. The opening travels on the L2 network instead.
type BudgetEntry struct {
	// Height is the L2 block height this allocation buys.
	Height uint32
	// Commitment is `consensus.PoseidonCommit(amount, random)`, a 64-char
	// lowercase hex string.
	Commitment string
}

// BudgetData is a budget cell's payload: the prepaid total, and the table
// dividing it among L2 heights.
type BudgetData struct {
	// Prepaid is the total moved into the mining addr in the same
	// transaction, in shannon. Plaintext, because a capacity transfer is
	// public on CKB anyway (ckb_layout.md §3).
	Prepaid uint64
	// Allocations is the table, ascending by height with no height twice.
	Allocations []BudgetEntry
}

// Encode renders the budget cell's data:
//
//	prepaid       u64 little-endian, 8 bytes
//	allocations   molecule fixvec of a 36-byte struct
//	                item count   u32 little-endian, 4 bytes
//	                item         height u32 LE ‖ commitment 32 bytes
//
// A molecule fixvec is exactly a count followed by the items, because every
// item is the same size; the offset table molecule uses for dynamic vectors
// would be pure overhead here.
//
// `d.Allocations` must be ascending by height with no duplicates, and every
// commitment must be 64 hex characters. Both are checked rather than assumed:
// the table is written once and can never be corrected (R3.1), so a table
// that encodes wrong is a prepayment thrown away.
func (d *BudgetData) Encode() ([]byte, error) {
	if err := d.validate(); err != nil {
		return nil, err
	}

	out := make([]byte, prepaidLen+fixvecHeaderLen+len(d.Allocations)*allocationLen)
	binary.LittleEndian.PutUint64(out[:prepaidLen], d.Prepaid)
	binary.LittleEndian.PutUint32(out[prepaidLen:prepaidLen+fixvecHeaderLen], uint32(len(d.Allocations)))

	at := prepaidLen + fixvecHeaderLen
	for _, entry := range d.Allocations {
		commitment, err := hex.DecodeString(entry.Commitment)
		if err != nil {
			return nil, fmt.Errorf("allocation for height %d: decoding the commitment: %w", entry.Height, err)
		}
		binary.LittleEndian.PutUint32(out[at:at+heightLen], entry.Height)
		copy(out[at+heightLen:at+allocationLen], commitment)
		at += allocationLen
	}
	return out, nil
}

// validate checks what Encode cannot fix up on the miner's behalf.
func (d *BudgetData) validate() error {
	var previous uint32
	for i, entry := range d.Allocations {
		if len(entry.Commitment) != commitmentLen*2 {
			return fmt.Errorf("allocation for height %d: commitment is %d hex characters, want %d",
				entry.Height, len(entry.Commitment), commitmentLen*2)
		}
		// Ascending order is what lets a reader stop early and what makes a
		// duplicate height impossible to miss; a duplicate would leave two
		// commitments claiming the same height with no rule to pick between.
		if i > 0 && entry.Height <= previous {
			return fmt.Errorf("allocations are not ascending by height: %d follows %d", entry.Height, previous)
		}
		previous = entry.Height
	}
	return nil
}

// DecodeBudgetData parses a budget cell's data back into its two parts.
//
// It is strict about trailing bytes. The data is what the whole cost model
// rests on and it is written once, so anything the encoding does not account
// for means this cell is not the shape it claims to be, and reading a total
// out of it anyway would be guessing.
func DecodeBudgetData(data []byte) (*BudgetData, error) {
	if len(data) < prepaidLen {
		return nil, fmt.Errorf("budget data is %d bytes, too short to hold the prepaid total", len(data))
	}
	out := &BudgetData{Prepaid: binary.LittleEndian.Uint64(data[:prepaidLen])}

	table := data[prepaidLen:]
	if len(table) == 0 {
		// A budget cell with no table at all: legal on chain, useless to a
		// miner, and distinct from a malformed one.
		return out, nil
	}
	if len(table) < fixvecHeaderLen {
		return nil, fmt.Errorf("allocation table is %d bytes, too short to hold its item count", len(table))
	}

	count := binary.LittleEndian.Uint32(table[:fixvecHeaderLen])
	body := table[fixvecHeaderLen:]
	// Checked before allocating: the count comes off the chain, and a bogus
	// one would otherwise reserve however much memory it names.
	if uint64(len(body)) != uint64(count)*allocationLen {
		return nil, fmt.Errorf("allocation table declares %d entries (%d bytes) but carries %d bytes",
			count, uint64(count)*allocationLen, len(body))
	}

	out.Allocations = make([]BudgetEntry, 0, count)
	for at := 0; at < len(body); at += allocationLen {
		out.Allocations = append(out.Allocations, BudgetEntry{
			Height:     binary.LittleEndian.Uint32(body[at : at+heightLen]),
			Commitment: hex.EncodeToString(body[at+heightLen : at+allocationLen]),
		})
	}
	if err := out.validate(); err != nil {
		return nil, err
	}
	return out, nil
}

// Lookup returns the commitment this table holds for `height`.
//
// The second result is false when the miner allocated nothing there, which is
// an ordinary answer rather than an error: a table covers the heights its
// owner chose to bid on and says nothing about the rest.
func (d *BudgetData) Lookup(height uint32) (string, bool) {
	for _, entry := range d.Allocations {
		if entry.Height == height {
			return entry.Commitment, true
		}
		// Ascending by construction, so the first height past the one asked
		// for settles it.
		if entry.Height > height {
			break
		}
	}
	return "", false
}

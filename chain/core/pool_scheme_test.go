package core

import (
	"math/big"
	"path/filepath"
	"testing"

	"gorm.io/gorm/logger"
)

// testAccount builds a minimal Account over a temp SQLite file — enough
// for the pool layer, which touches only `db`, `cfg`, and `pool`.
func testAccount(t *testing.T, cfg *AccountConfig) *Account {
	t.Helper()
	if cfg == nil {
		cfg = &AccountConfig{}
	}
	if cfg.DBPath == "" {
		cfg.DBPath = filepath.Join(t.TempDir(), "accounts.db")
	}
	a := &Account{
		db:  InitAccountDB(cfg.DBPath, logger.Silent),
		cfg: cfg,
	}
	if err := a.InitPool(); err != nil {
		t.Fatalf("InitPool: %v", err)
	}
	return a
}

// reopen builds a second Account over the same database file, simulating a
// chain restart.
func reopen(t *testing.T, a *Account) *Account {
	t.Helper()
	return testAccount(t, &AccountConfig{DBPath: a.cfg.DBPath, GenesisNote: a.cfg.GenesisNote})
}

func cmOf(v int64) *big.Int { return Poseidon2(big.NewInt(TagCM), big.NewInt(v)) }

// A failed mutation (duplicate nullifier) must roll back EVERYTHING: no
// note appended, frontier unchanged, no anchor recorded.
func TestPoolMutationIsAtomic(t *testing.T) {
	a := testAccount(t, nil)

	if _, err := a.ApplyPoolMutation(PoolMutation{
		Nullifiers: []string{FrToHex(big.NewInt(111))},
		NoteCms:    []*big.Int{cmOf(1)},
		Source:     "test",
	}); err != nil {
		t.Fatalf("first mutation: %v", err)
	}
	rootBefore := a.PoolRoot()
	sizeBefore := a.PoolSize()

	// Same nullifier again: primary-key conflict inside the transaction.
	_, err := a.ApplyPoolMutation(PoolMutation{
		Nullifiers: []string{FrToHex(big.NewInt(111))},
		NoteCms:    []*big.Int{cmOf(2)},
		Source:     "test",
	})
	if err == nil {
		t.Fatal("duplicate nullifier must fail the whole mutation")
	}
	if a.PoolRoot() != rootBefore || a.PoolSize() != sizeBefore {
		t.Fatal("failed mutation must leave the frontier untouched")
	}
	notes, err := a.FindNotes(0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(notes) != 1 {
		t.Fatalf("note append must have rolled back, found %d notes", len(notes))
	}

	// The pool still works after the rollback.
	if _, err := a.ApplyPoolMutation(PoolMutation{
		Nullifiers: []string{FrToHex(big.NewInt(222))},
		NoteCms:    []*big.Int{cmOf(3)},
		Source:     "test",
	}); err != nil {
		t.Fatalf("mutation after rollback: %v", err)
	}
}

// A restart (fresh Account over the same DB) must restore the identical
// frontier — from the snapshot, and, when the snapshot is corrupted, by
// replaying the notes table (self-healing).
func TestPoolRestartRestoresFrontier(t *testing.T) {
	a := testAccount(t, nil)
	for i := int64(0); i < 5; i++ {
		if _, err := a.ApplyPoolMutation(PoolMutation{
			NoteCms: []*big.Int{cmOf(i)},
			Source:  "test",
		}); err != nil {
			t.Fatal(err)
		}
	}
	root := a.PoolRoot()

	b := reopen(t, a)
	if b.PoolRoot() != root || b.PoolSize() != 5 {
		t.Fatal("restart must restore the frontier from the snapshot")
	}

	// Corrupt the snapshot; the replay path must reproduce the same root.
	if err := a.db.Model(&TreeStateScheme{}).Where("id = ?", 1).
		Update("frontier_json", "{broken").Error; err != nil {
		t.Fatal(err)
	}
	c := reopen(t, a)
	if c.PoolRoot() != root || c.PoolSize() != 5 {
		t.Fatal("corrupted snapshot must self-heal by replaying notes")
	}
}

// Genesis seeding runs on every boot: a second boot must be a no-op, a
// partial seed must be completed, and a drifted chain must refuse to start.
func TestGenesisNoteSeedingIsIdempotent(t *testing.T) {
	genesis := []GenesisNote{
		{Cm: FrToHex(cmOf(10)), Memo: "alice"},
		{Cm: FrToHex(cmOf(11)), Memo: "bob"},
		{Cm: FrToHex(cmOf(12)), Memo: "carol"},
	}
	a := testAccount(t, &AccountConfig{GenesisNote: genesis})

	a.seedGenesisNotes(0)
	root := a.PoolRoot()
	if a.PoolSize() != 3 {
		t.Fatalf("expected 3 genesis leaves, got %d", a.PoolSize())
	}

	// Second boot: same config, same DB — nothing may change.
	b := reopen(t, a)
	b.seedGenesisNotes(0)
	if b.PoolRoot() != root || b.PoolSize() != 3 {
		t.Fatal("re-seeding on restart must be a no-op")
	}

	// Partial seed: a chain that crashed after 3 leaves, now configured
	// with 4, must append exactly the missing suffix.
	extended := append(append([]GenesisNote{}, genesis...), GenesisNote{Cm: FrToHex(cmOf(13))})
	c := testAccount(t, &AccountConfig{DBPath: a.cfg.DBPath, GenesisNote: extended})
	c.seedGenesisNotes(0)
	if c.PoolSize() != 4 {
		t.Fatalf("extended genesis must append the suffix, got %d leaves", c.PoolSize())
	}

	// Drift: config disagreeing with chain history must panic.
	drifted := append([]GenesisNote{}, extended...)
	drifted[0].Cm = FrToHex(cmOf(99))
	d := testAccount(t, &AccountConfig{DBPath: a.cfg.DBPath, GenesisNote: drifted})
	defer func() {
		if recover() == nil {
			t.Fatal("drifted genesis must panic")
		}
	}()
	d.seedGenesisNotes(0)
}

// Anchor bookkeeping: every distinct root is recorded and stays valid;
// the empty root is always known.
func TestAnchorsAccumulate(t *testing.T) {
	a := testAccount(t, nil)
	known, err := a.AnchorKnown(FrToHex(EmptyRoot(TreeDepth)))
	if err != nil || !known {
		t.Fatal("empty root must always be a valid anchor")
	}

	var roots []string
	for i := int64(0); i < 3; i++ {
		if _, err := a.ApplyPoolMutation(PoolMutation{
			NoteCms: []*big.Int{cmOf(i)},
			Source:  "test",
		}); err != nil {
			t.Fatal(err)
		}
		roots = append(roots, a.PoolRoot())
	}
	for _, r := range roots {
		known, err := a.AnchorKnown(r)
		if err != nil || !known {
			t.Fatalf("historical root %s must stay a valid anchor", r)
		}
	}
	unknown, err := a.AnchorKnown(FrToHex(big.NewInt(12345)))
	if err != nil || unknown {
		t.Fatal("a fabricated root must not be a valid anchor")
	}
}

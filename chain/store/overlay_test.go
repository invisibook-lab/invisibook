package store

import "testing"

type row struct {
	ID     string
	Status int
}

func key(r row) string { return r.ID }

func ids(rows []row) map[string]int {
	out := make(map[string]int, len(rows))
	for _, r := range rows {
		out[r.ID] = r.Status
	}
	return out
}

// TestOverlayReplacesChangedRows: a key an unsettled block touched is seen in
// the state that block left it, not the settled one underneath.
func TestOverlayReplacesChangedRows(t *testing.T) {
	main := []row{{"a", 0}, {"b", 0}}
	staged := map[string]Staged[row]{"a": {Row: row{"a", 1}}}

	got := ids(Overlay(main, staged, key))
	if got["a"] != 1 {
		t.Fatalf("a = %d, want the staged status 1", got["a"])
	}
	if got["b"] != 0 {
		t.Fatalf("b = %d, want the settled status 0 — it was never staged", got["b"])
	}
}

// TestOverlayDropsDeletedRows: a block that removed a record makes it invisible
// even though the settled table still holds it.
func TestOverlayDropsDeletedRows(t *testing.T) {
	main := []row{{"a", 0}, {"b", 0}}
	staged := map[string]Staged[row]{"a": {Row: row{"a", 0}, Deleted: true}}

	got := Overlay(main, staged, key)
	if len(got) != 1 || got[0].ID != "b" {
		t.Fatalf("Overlay = %+v, want only b", got)
	}
}

// TestOverlayAddsCreatedRows: a record an unsettled block created exists only
// in the staged view and must still be returned.
func TestOverlayAddsCreatedRows(t *testing.T) {
	main := []row{{"a", 0}}
	staged := map[string]Staged[row]{"c": {Row: row{"c", 2}}}

	got := ids(Overlay(main, staged, key))
	if len(got) != 2 || got["c"] != 2 {
		t.Fatalf("Overlay = %+v, want a and the newly created c", got)
	}
}

// TestOverlayIgnoresDeletedRowsWithNoCounterpart: a record created and removed
// before ever being settled must not surface.
func TestOverlayIgnoresDeletedRowsWithNoCounterpart(t *testing.T) {
	staged := map[string]Staged[row]{"c": {Row: row{"c", 0}, Deleted: true}}
	if got := Overlay(nil, staged, key); len(got) != 0 {
		t.Fatalf("Overlay = %+v, want nothing", got)
	}
}

func TestOverlayWithNothingStagedReturnsMain(t *testing.T) {
	main := []row{{"a", 0}, {"b", 1}}
	if got := Overlay(main, nil, key); len(got) != 2 {
		t.Fatalf("Overlay = %+v, want both settled rows", got)
	}
}

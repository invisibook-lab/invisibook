package store

// Staged is the state an unsettled block left a key in: the row as it would
// look, or a marker that the block removed it.
type Staged[T any] struct {
	Row     T
	Deleted bool
}

// Overlay merges staged rows over a result set read from a main table.
//
// A key present in `staged` takes the staged version; one staged as deleted
// disappears; a staged key with no counterpart in `main` is appended. The
// result is what the table would look like if every unsettled block were
// already applied.
//
// The caller must re-apply its own filter to the result. A query narrows on
// some field — a cash's status, an order's state — and the staged row may have
// changed that very field, so a row that qualified in the main table may no
// longer qualify, and one that did not may now.
//
// `key` must return the identity a row is versioned by, and must be stable:
// two rows for the same logical record must produce the same key.
func Overlay[T any](main []T, staged map[string]Staged[T], key func(T) string) []T {
	merged := make([]T, 0, len(main)+len(staged))
	seen := make(map[string]bool, len(main))

	for _, row := range main {
		k := key(row)
		seen[k] = true
		if s, ok := staged[k]; ok {
			if s.Deleted {
				continue
			}
			merged = append(merged, s.Row)
			continue
		}
		merged = append(merged, row)
	}

	// Records an unsettled block created have no counterpart to replace.
	for k, s := range staged {
		if seen[k] || s.Deleted {
			continue
		}
		merged = append(merged, s.Row)
	}
	return merged
}

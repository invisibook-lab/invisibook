package config

import (
	"os"
	"path/filepath"
	"testing"
)

// TestConsensusConfigLoading preserves old PoB configs while rejecting explicit invalid selections.
func TestConsensusConfigLoading(t *testing.T) {
	for _, tc := range []struct {
		name, text string
		fail       bool
	}{
		{"legacy", "[consensus]\nmin_payment = \"100\"\n", false},
		{"unknown", "[consensus]\nengine = \"unknown\"\n", true},
		{"malformed", "[consensus\n", true},
		{"incomplete poa", "[consensus]\nengine = \"poa\"\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "core.toml")
			if err := os.WriteFile(p, []byte(tc.text), 0600); err != nil {
				t.Fatal(err)
			}
			cfg, err := Load(p)
			if tc.fail {
				if err == nil {
					t.Fatal("invalid configuration accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if cfg.Consensus.Engine != "pob" {
				t.Fatal("legacy default changed")
			}
		})
	}
}

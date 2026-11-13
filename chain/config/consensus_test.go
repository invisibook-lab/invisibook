package config

import (
	"os"
	"path/filepath"
	"testing"
)

// TestConsensusConfigLoading validates engine selection and separate PoB settings.
func TestConsensusConfigLoading(t *testing.T) {
	for _, tc := range []struct {
		name, text string
		fail       bool
	}{
		{"pob", "[consensus]\nengine = \"pob\"\n[pob]\npack_num = 17\n", false},
		{"default", "", false},
		{"old section", "[consensus]\npack_num = 17\n", true},
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
				t.Fatal("default engine changed")
			}
			if tc.name == "pob" && cfg.PoB.PackNum != 17 {
				t.Fatal("PoB settings were not loaded from [pob]")
			}
		})
	}
}

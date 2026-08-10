package nemesis

import (
	"encoding/json"
	"os"
	"testing"
)

// TestNormalizePathParity asserts the Go path tokenizer is byte-identical to the canonical
// cross-SDK vectors (../tokenize.vectors.json, key "normalizePath"). All vectors must pass.
func TestNormalizePathParity(t *testing.T) {
	raw, err := os.ReadFile("../tokenize.vectors.json")
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var doc struct {
		NormalizePath []struct {
			Path   string `json:"path"`
			Expect string `json:"expect"`
			Why    string `json:"why"`
		} `json:"normalizePath"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	if len(doc.NormalizePath) == 0 {
		t.Fatal("no normalizePath vectors found")
	}
	pass := 0
	for _, v := range doc.NormalizePath {
		got := normalizePath(v.Path)
		if got != v.Expect {
			t.Errorf("normalizePath(%q) = %q; want %q (%s)", v.Path, got, v.Expect, v.Why)
			continue
		}
		pass++
	}
	t.Logf("parity: %d/%d", pass, len(doc.NormalizePath))
}

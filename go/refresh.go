// Central model hot-swap for the Go SDK. Pulls a newer signed HashLR model from a cloud URL and swaps
// it in place, so the model can be retrained and pushed centrally without redeploying the SDK.
// Fail-safe: on any error the current (embedded) model is kept. Ed25519 verify uses the stdlib.
package nemesis

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"time"
)

// Ed25519 public key (hex) that signs published models. Cloud pulls MUST carry a valid signature over
// the exact bytes; unsigned or tampered bundles are rejected and the embedded model is kept.
const modelPublicKeyHex = "79d81a3b41966b379a9ba719155b8713f70bb341c3e8fab09fd5563a59893d28"

// ModelVersion returns the version of the model currently loaded (embedded, or a hot-swapped one).
func ModelVersion() int { return ml.Version }

func verifyModelSignature(raw []byte, sigB64 string) bool {
	if modelPublicKeyHex == "" {
		return true // no key pinned - version gate + HTTPS still apply
	}
	if sigB64 == "" {
		return false // key pinned but bundle unsigned - reject
	}
	pk, err := hex.DecodeString(modelPublicKeyHex)
	if err != nil || len(pk) != ed25519.PublicKeySize {
		return false
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pk), raw, sig)
}

// RefreshModel hot-swaps the HashLR model from url (or env NEMESIS_MODEL_URL) if a newer signed
// version is published. Returns the new version number if updated, else 0.
func RefreshModel(url string) int {
	if url == "" {
		url = os.Getenv("NEMESIS_MODEL_URL")
	}
	if url == "" {
		return 0
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0
	}
	if !verifyModelSignature(raw, resp.Header.Get("X-Model-Signature")) {
		return 0 // integrity gate
	}
	var m mlModel
	if err := json.Unmarshal(raw, &m); err != nil {
		return 0
	}
	if m.Version <= ml.Version || (m.Dim != 0 && m.Dim != ml.Dim) {
		return 0 // version / dim gate (feature space is fixed across versions)
	}
	ml = m
	return ml.Version
}

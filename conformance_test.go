// Copyright 2026 Quantum Pipes Technologies, LLC
// SPDX-License-Identifier: Apache-2.0

package capsule_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	capsule "github.com/quantumpipes/capsule-go"
)

// ── Fixture loading ────────────────────────────────────────────────

type fixture struct {
	Name          string         `json:"name"`
	Description   string         `json:"description"`
	CapsuleDict   map[string]any `json:"capsule_dict"`
	CanonicalJSON string         `json:"canonical_json"`
	SHA3Hash      string         `json:"sha3_256_hash"`
}

type fixtureFile struct {
	Version  string    `json:"version"`
	Fixtures []fixture `json:"fixtures"`
}

func loadFixtures(t *testing.T) []fixture {
	t.Helper()
	data, err := os.ReadFile("testdata/fixtures.json")
	if err != nil {
		t.Fatalf("read fixtures: %v", err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var ff fixtureFile
	if err := dec.Decode(&ff); err != nil {
		t.Fatalf("decode fixtures: %v", err)
	}
	return ff.Fixtures
}

// ── Golden vector conformance (16 fixtures) ────────────────────────

func TestConformance_CanonicalJSON(t *testing.T) {
	fixtures := loadFixtures(t)
	if len(fixtures) != 16 {
		t.Fatalf("expected 16 fixtures, got %d", len(fixtures))
	}
	for _, f := range fixtures {
		t.Run(f.Name, func(t *testing.T) {
			got := capsule.Canonicalize(f.CapsuleDict)
			if got != f.CanonicalJSON {
				t.Errorf("canonical JSON mismatch\nwant: %s\ngot:  %s", f.CanonicalJSON, got)
			}
		})
	}
}

func TestConformance_SHA3Hash(t *testing.T) {
	for _, f := range loadFixtures(t) {
		t.Run(f.Name, func(t *testing.T) {
			got := capsule.Hash(capsule.Canonicalize(f.CapsuleDict))
			if got != f.SHA3Hash {
				t.Errorf("hash mismatch\nwant: %s\ngot:  %s", f.SHA3Hash, got)
			}
		})
	}
}

func TestConformance_VerifyHash(t *testing.T) {
	for _, f := range loadFixtures(t) {
		t.Run(f.Name, func(t *testing.T) {
			if !capsule.VerifyHash(f.CapsuleDict, f.SHA3Hash) {
				t.Error("VerifyHash returned false")
			}
		})
	}
}

// ── Hash function ──────────────────────────────────────────────────

func TestHash_KnownVector(t *testing.T) {
	// SHA3-256("") = a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a
	got := capsule.Hash("")
	want := "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
	if got != want {
		t.Errorf("SHA3-256 of empty string\nwant: %s\ngot:  %s", want, got)
	}
}

func TestHash_Deterministic(t *testing.T) {
	a := capsule.Hash("hello world")
	b := capsule.Hash("hello world")
	if a != b {
		t.Error("Hash should be deterministic")
	}
	if len(a) != 64 {
		t.Errorf("hash length: want 64, got %d", len(a))
	}
}

// ── VerifyHash ─────────────────────────────────────────────────────

func TestVerifyHash_Tampered(t *testing.T) {
	fixtures := loadFixtures(t)
	original := fixtures[0]
	tampered := make(map[string]any, len(original.CapsuleDict))
	for k, v := range original.CapsuleDict {
		tampered[k] = v
	}
	tampered["domain"] = "tampered"
	if capsule.VerifyHash(tampered, original.SHA3Hash) {
		t.Error("should reject tampered content")
	}
}

func TestVerifyHash_WrongHash(t *testing.T) {
	fixtures := loadFixtures(t)
	if capsule.VerifyHash(fixtures[0].CapsuleDict, "0000000000000000000000000000000000000000000000000000000000000000") {
		t.Error("should reject wrong hash")
	}
}

// ── Ed25519 signature verification ─────────────────────────────────

func TestVerifySignature_ValidRoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	hashHex := "e6266f6d907a02e1f3531dc354765c0bca506180b91c1f5892a544b81bcf8dee"
	sig := ed25519.Sign(priv, []byte(hashHex))

	pubHex := hex.EncodeToString(pub)
	sigHex := hex.EncodeToString(sig)

	if !capsule.VerifySignature(hashHex, sigHex, pubHex) {
		t.Error("valid signature rejected")
	}
}

func TestVerifySignature_WrongKey(t *testing.T) {
	pub1, priv1, _ := ed25519.GenerateKey(nil)
	pub2, _, _ := ed25519.GenerateKey(nil)
	_ = pub1

	hashHex := "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234"
	sig := ed25519.Sign(priv1, []byte(hashHex))

	if capsule.VerifySignature(hashHex, hex.EncodeToString(sig), hex.EncodeToString(pub2)) {
		t.Error("should reject signature from wrong key")
	}
}

func TestVerifySignature_InvalidHex(t *testing.T) {
	if capsule.VerifySignature("abc", "def", "ghi") {
		t.Error("should reject invalid hex")
	}
}

func TestVerifySignature_WrongLengths(t *testing.T) {
	if capsule.VerifySignature("aa", "bb", "cc") {
		t.Error("should reject wrong-length values")
	}
}

func TestVerifySignature_TamperedHash(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	hashHex := "e6266f6d907a02e1f3531dc354765c0bca506180b91c1f5892a544b81bcf8dee"
	sig := ed25519.Sign(priv, []byte(hashHex))
	tampered := "f6266f6d907a02e1f3531dc354765c0bca506180b91c1f5892a544b81bcf8dee"

	if capsule.VerifySignature(tampered, hex.EncodeToString(sig), hex.EncodeToString(pub)) {
		t.Error("should reject when hash was tampered after signing")
	}
}

// ── ExtractSealed ──────────────────────────────────────────────────

func TestExtractSealed_AllFields(t *testing.T) {
	raw := map[string]any{
		"id": "test-id", "type": "agent",
		"hash": "abc123", "signature": "sig456",
		"signed_by": "key789", "signed_at": "2026-01-01T00:00:00+00:00",
		"signature_pq": "",
	}
	sc := capsule.ExtractSealed(raw)
	if sc.Hash != "abc123" || sc.Signature != "sig456" || sc.SignedBy != "key789" {
		t.Error("seal fields not extracted")
	}
	for _, f := range capsule.SealFields {
		if _, ok := sc.Content[f]; ok {
			t.Errorf("seal field %q not removed from content", f)
		}
	}
	if sc.Content["id"] != "test-id" {
		t.Error("content field lost")
	}
}

func TestExtractSealed_NoSealFields(t *testing.T) {
	raw := map[string]any{"id": "bare", "type": "agent"}
	sc := capsule.ExtractSealed(raw)
	if sc.Hash != "" || sc.Signature != "" || sc.SignedBy != "" {
		t.Error("empty seal fields should be zero-value")
	}
	if sc.Content["id"] != "bare" {
		t.Error("content should be preserved")
	}
}

func TestExtractSealed_DoesNotMutateOriginal(t *testing.T) {
	raw := map[string]any{"id": "orig", "hash": "h1"}
	_ = capsule.ExtractSealed(raw)
	if _, ok := raw["hash"]; !ok {
		t.Error("original map should not be mutated")
	}
}

// ── Chain verification ─────────────────────────────────────────────

func makeChain(n int) []capsule.SealedCapsule {
	chain := make([]capsule.SealedCapsule, n)
	for i := 0; i < n; i++ {
		content := map[string]any{
			"id":       json.Number("0"),
			"type":     "agent",
			"domain":   "test",
			"sequence": json.Number(jsonInt(i)),
		}
		if i == 0 {
			content["previous_hash"] = nil
		} else {
			content["previous_hash"] = chain[i-1].Hash
		}
		canonical := capsule.Canonicalize(content)
		hash := capsule.Hash(canonical)
		chain[i] = capsule.SealedCapsule{Content: content, Hash: hash}
	}
	return chain
}

func jsonInt(n int) string {
	buf, _ := json.Marshal(n)
	return string(buf)
}

func TestChainStructural_Empty(t *testing.T) {
	if errs := capsule.VerifyChainStructural(nil); len(errs) != 0 {
		t.Errorf("empty chain should have no errors, got %v", errs)
	}
}

func TestChainStructural_ValidChain(t *testing.T) {
	chain := makeChain(5)
	if errs := capsule.VerifyChainStructural(chain); len(errs) != 0 {
		t.Errorf("valid chain should pass, got %v", errs)
	}
}

func TestChainStructural_SingleGenesis(t *testing.T) {
	chain := makeChain(1)
	if errs := capsule.VerifyChainStructural(chain); len(errs) != 0 {
		t.Errorf("single genesis should pass, got %v", errs)
	}
}

func TestChainStructural_NonZeroGenesis(t *testing.T) {
	chain := makeChain(1)
	chain[0].Content["sequence"] = json.Number("5")
	errs := capsule.VerifyChainStructural(chain)
	if len(errs) == 0 {
		t.Error("should detect non-zero genesis sequence")
	}
}

func TestChainStructural_GenesisWithPreviousHash(t *testing.T) {
	chain := makeChain(1)
	chain[0].Content["previous_hash"] = "aaaa"
	errs := capsule.VerifyChainStructural(chain)
	if len(errs) == 0 {
		t.Error("should detect genesis with non-null previous_hash")
	}
}

func TestChainStructural_WrongSequence(t *testing.T) {
	chain := makeChain(3)
	chain[2].Content["sequence"] = json.Number("5")
	errs := capsule.VerifyChainStructural(chain)
	if len(errs) == 0 {
		t.Error("should detect sequence gap")
	}
}

func TestChainStructural_WrongPreviousHash(t *testing.T) {
	chain := makeChain(3)
	chain[2].Content["previous_hash"] = "bad_hash"
	errs := capsule.VerifyChainStructural(chain)
	if len(errs) == 0 {
		t.Error("should detect previous_hash mismatch")
	}
}

func TestChainFull_ValidChain(t *testing.T) {
	chain := makeChain(3)
	if errs := capsule.VerifyChainFull(chain); len(errs) != 0 {
		t.Errorf("valid chain should pass full verification, got %v", errs)
	}
}

func TestChainFull_TamperedContent(t *testing.T) {
	chain := makeChain(3)
	chain[1].Content["domain"] = "tampered"
	errs := capsule.VerifyChainFull(chain)
	if len(errs) == 0 {
		t.Error("should detect tampered content via hash recomputation")
	}
}

func TestChainSignatures_MissingSignature(t *testing.T) {
	chain := makeChain(1)
	resolver := func(string) string { return "" }
	errs := capsule.VerifyChainSignatures(chain, resolver)
	found := false
	for _, e := range errs {
		if e.Error() == "capsule 0: missing signature" {
			found = true
		}
	}
	if !found {
		t.Errorf("should report missing signature, got %v", errs)
	}
}

func TestChainSignatures_NoKeyForFingerprint(t *testing.T) {
	chain := makeChain(1)
	chain[0].Signature = "aa"
	chain[0].SignedBy = "unknown_fp"
	resolver := func(string) string { return "" }
	errs := capsule.VerifyChainSignatures(chain, resolver)
	found := false
	for _, e := range errs {
		if e != nil {
			found = true
		}
	}
	if !found {
		t.Error("should report no key for fingerprint")
	}
}

// ── Canonicalize unit tests ────────────────────────────────────────

func TestCanonicalize_EmptyObject(t *testing.T) {
	got := capsule.Canonicalize(map[string]any{})
	if got != "{}" {
		t.Errorf("want {}, got %s", got)
	}
}

func TestCanonicalize_KeySorting(t *testing.T) {
	m := map[string]any{"z": "last", "a": "first", "m": "middle"}
	got := capsule.Canonicalize(m)
	want := `{"a":"first","m":"middle","z":"last"}`
	if got != want {
		t.Errorf("key sorting\nwant: %s\ngot:  %s", want, got)
	}
}

func TestCanonicalize_NestedKeySorting(t *testing.T) {
	m := map[string]any{
		"b": map[string]any{"z": json.Number("1"), "a": json.Number("2")},
		"a": "first",
	}
	got := capsule.Canonicalize(m)
	want := `{"a":"first","b":{"a":2,"z":1}}`
	if got != want {
		t.Errorf("nested sorting\nwant: %s\ngot:  %s", want, got)
	}
}

func TestCanonicalize_ArrayOrderPreserved(t *testing.T) {
	m := map[string]any{"arr": []any{json.Number("3"), json.Number("1"), json.Number("2")}}
	got := capsule.Canonicalize(m)
	want := `{"arr":[3,1,2]}`
	if got != want {
		t.Errorf("array order\nwant: %s\ngot:  %s", want, got)
	}
}

func TestCanonicalize_NullBoolTypes(t *testing.T) {
	m := map[string]any{"n": nil, "t": true, "f": false}
	got := capsule.Canonicalize(m)
	want := `{"f":false,"n":null,"t":true}`
	if got != want {
		t.Errorf("null/bool\nwant: %s\ngot:  %s", want, got)
	}
}

func TestCanonicalize_UTF8Passthrough(t *testing.T) {
	m := map[string]any{"text": "cafe\u0301 \u2603 \u2764"}
	got := capsule.Canonicalize(m)
	if got != `{"text":"café ☃ ❤"}` {
		t.Errorf("UTF-8 passthrough failed: %s", got)
	}
}

func TestCanonicalize_SolidusNotEscaped(t *testing.T) {
	m := map[string]any{"url": "https://example.com/path"}
	got := capsule.Canonicalize(m)
	want := `{"url":"https://example.com/path"}`
	if got != want {
		t.Errorf("solidus should not be escaped\nwant: %s\ngot:  %s", want, got)
	}
}

func TestCanonicalize_ControlCharEscaped(t *testing.T) {
	m := map[string]any{"s": "tab\there"}
	got := capsule.Canonicalize(m)
	want := `{"s":"tab\u0009here"}`
	if got != want {
		t.Errorf("control char escaping\nwant: %s\ngot:  %s", want, got)
	}
}

func TestCanonicalize_QuotesAndBackslash(t *testing.T) {
	m := map[string]any{"s": `say "hello" \n`}
	got := capsule.Canonicalize(m)
	want := `{"s":"say \"hello\" \\n"}`
	if got != want {
		t.Errorf("quote/backslash escaping\nwant: %s\ngot:  %s", want, got)
	}
}

func TestCanonicalize_EmptyStringVsNull(t *testing.T) {
	m := map[string]any{"empty": "", "null": nil}
	got := capsule.Canonicalize(m)
	want := `{"empty":"","null":null}`
	if got != want {
		t.Errorf("empty vs null\nwant: %s\ngot:  %s", want, got)
	}
}

func TestCanonicalize_FloatPathEnforced(t *testing.T) {
	m := map[string]any{
		"reasoning": map[string]any{
			"confidence": json.Number("1"),
		},
	}
	got := capsule.Canonicalize(m)
	want := `{"reasoning":{"confidence":1.0}}`
	if got != want {
		t.Errorf("float path enforcement\nwant: %s\ngot:  %s", want, got)
	}
}

func TestCanonicalize_FloatPathInArray(t *testing.T) {
	m := map[string]any{
		"reasoning": map[string]any{
			"options": []any{
				map[string]any{"feasibility": json.Number("0")},
			},
		},
	}
	got := capsule.Canonicalize(m)
	want := `{"reasoning":{"options":[{"feasibility":0.0}]}}`
	if got != want {
		t.Errorf("float path in array\nwant: %s\ngot:  %s", want, got)
	}
}

func TestCanonicalize_NonFloatPathInteger(t *testing.T) {
	m := map[string]any{"execution": map[string]any{"duration_ms": json.Number("0")}}
	got := capsule.Canonicalize(m)
	want := `{"execution":{"duration_ms":0}}`
	if got != want {
		t.Errorf("non-float int should stay integer\nwant: %s\ngot:  %s", want, got)
	}
}

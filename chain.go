// Copyright 2026 Quantum Pipes Technologies, LLC
// SPDX-License-Identifier: Apache-2.0

package capsule

import (
	"encoding/json"
	"fmt"
)

// SealFields are the metadata keys added during sealing.
// They are excluded from canonical content.
var SealFields = []string{"hash", "signature", "signature_pq", "signed_at", "signed_by"}

// SealedCapsule holds a capsule's content (seal fields removed) alongside
// the seal metadata needed for verification.
type SealedCapsule struct {
	Content   map[string]any
	Hash      string
	Signature string
	SignedBy  string
}

// ExtractSealed splits a raw capsule map into content and seal metadata.
// The returned SealedCapsule.Content has all seal fields removed.
func ExtractSealed(raw map[string]any) SealedCapsule {
	content := make(map[string]any, len(raw))
	for k, v := range raw {
		content[k] = v
	}

	sc := SealedCapsule{}
	if h, ok := content["hash"].(string); ok {
		sc.Hash = h
	}
	if s, ok := content["signature"].(string); ok {
		sc.Signature = s
	}
	if sb, ok := content["signed_by"].(string); ok {
		sc.SignedBy = sb
	}

	for _, f := range SealFields {
		delete(content, f)
	}
	sc.Content = content
	return sc
}

// VerifyChainStructural checks sequence continuity and hash linkage (CPS Section 7.5 level 1).
func VerifyChainStructural(capsules []SealedCapsule) []error {
	if len(capsules) == 0 {
		return nil
	}

	var errs []error

	seq0, ok := getSequence(capsules[0].Content)
	if !ok {
		errs = append(errs, fmt.Errorf("capsule 0: missing or invalid sequence"))
	} else if seq0 != 0 {
		errs = append(errs, fmt.Errorf("capsule 0: sequence is %d, expected 0", seq0))
	}

	ph0, _ := getPreviousHash(capsules[0].Content)
	if ph0 != "" {
		errs = append(errs, fmt.Errorf("capsule 0: genesis must have null previous_hash"))
	}

	for i := 1; i < len(capsules); i++ {
		seq, ok := getSequence(capsules[i].Content)
		if !ok {
			errs = append(errs, fmt.Errorf("capsule %d: missing or invalid sequence", i))
			continue
		}
		if seq != int64(i) {
			errs = append(errs, fmt.Errorf("capsule %d: sequence is %d, expected %d", i, seq, i))
		}

		ph, _ := getPreviousHash(capsules[i].Content)
		if ph != capsules[i-1].Hash {
			errs = append(errs, fmt.Errorf("capsule %d: previous_hash does not match hash of capsule %d", i, i-1))
		}
	}

	return errs
}

// VerifyChainFull performs structural verification plus SHA3-256 recomputation
// for each capsule (CPS Section 7.5 level 2).
func VerifyChainFull(capsules []SealedCapsule) []error {
	errs := VerifyChainStructural(capsules)

	for i, c := range capsules {
		if !VerifyHash(c.Content, c.Hash) {
			errs = append(errs, fmt.Errorf("capsule %d: recomputed hash does not match stored hash", i))
		}
	}

	return errs
}

// VerifyChainSignatures performs full verification plus Ed25519 signature
// checks using the provided public key resolver.
func VerifyChainSignatures(capsules []SealedCapsule, resolveKey func(fingerprint string) string) []error {
	errs := VerifyChainFull(capsules)

	for i, c := range capsules {
		if c.Signature == "" {
			errs = append(errs, fmt.Errorf("capsule %d: missing signature", i))
			continue
		}
		pubHex := resolveKey(c.SignedBy)
		if pubHex == "" {
			errs = append(errs, fmt.Errorf("capsule %d: no public key for fingerprint %q", i, c.SignedBy))
			continue
		}
		if !VerifySignature(c.Hash, c.Signature, pubHex) {
			errs = append(errs, fmt.Errorf("capsule %d: Ed25519 signature verification failed", i))
		}
	}

	return errs
}

func getSequence(content map[string]any) (int64, bool) {
	v, ok := content["sequence"]
	if !ok {
		return 0, false
	}
	switch n := v.(type) {
	case json.Number:
		i, err := n.Int64()
		return i, err == nil
	case float64:
		return int64(n), true
	default:
		return 0, false
	}
}

func getPreviousHash(content map[string]any) (string, bool) {
	v, ok := content["previous_hash"]
	if !ok {
		return "", false
	}
	if v == nil {
		return "", true
	}
	s, ok := v.(string)
	return s, ok
}

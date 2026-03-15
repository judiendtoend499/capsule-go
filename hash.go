// Copyright 2026 Quantum Pipes Technologies, LLC
// SPDX-License-Identifier: Apache-2.0

package capsule

import (
	"crypto/ed25519"
	"encoding/hex"

	"golang.org/x/crypto/sha3"
)

// Hash computes the SHA3-256 hex digest of a canonical JSON string (CPS Section 3.1).
func Hash(canonicalJSON string) string {
	h := sha3.New256()
	h.Write([]byte(canonicalJSON))
	return hex.EncodeToString(h.Sum(nil))
}

// VerifyHash canonicalizes a capsule dict, computes SHA3-256, and compares
// to the expected hash. Returns true if they match.
func VerifyHash(capsuleDict map[string]any, expectedHash string) bool {
	return Hash(Canonicalize(capsuleDict)) == expectedHash
}

// VerifySignature verifies an Ed25519 signature over a hash hex string.
//
// Per CPS Section 3.2, the signature is computed over the hex-encoded hash
// STRING (64 ASCII characters as UTF-8), not the raw 32-byte hash value.
func VerifySignature(hashHex, signatureHex, publicKeyHex string) bool {
	pubBytes, err := hex.DecodeString(publicKeyHex)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		return false
	}

	sigBytes, err := hex.DecodeString(signatureHex)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return false
	}

	return ed25519.Verify(ed25519.PublicKey(pubBytes), []byte(hashHex), sigBytes)
}

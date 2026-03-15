# capsule-go

Go verifier library for the [Capsule Protocol Specification (CPS)](https://github.com/quantumpipes/capsule).

Verify capsule integrity, chain linkage, and Ed25519 signatures in Go. Passes all 16 golden conformance vectors.

## Install

```bash
go get github.com/quantumpipes/capsule-go
```

## Usage

### Verify a capsule hash

```go
import capsule "github.com/quantumpipes/capsule-go"

// capsuleDict is a map[string]any decoded with json.Decoder.UseNumber()
valid := capsule.VerifyHash(capsuleDict, expectedHash)
```

### Canonical JSON and SHA3-256

```go
canonical := capsule.Canonicalize(capsuleDict)
hash := capsule.Hash(canonical)
```

### Verify an Ed25519 signature

```go
// CPS signs the hex hash STRING (64 ASCII chars), not raw bytes
valid := capsule.VerifySignature(hashHex, signatureHex, publicKeyHex)
```

### Chain verification

```go
// Structural: sequence continuity + hash linkage
errs := capsule.VerifyChainStructural(sealedCapsules)

// Full: structural + SHA3-256 recomputation
errs := capsule.VerifyChainFull(sealedCapsules)

// Signatures: full + Ed25519 verification
errs := capsule.VerifyChainSignatures(sealedCapsules, func(fingerprint string) string {
    return keyring[fingerprint] // return public key hex for this fingerprint
})
```

### Parse sealed capsules from JSON

```go
dec := json.NewDecoder(file)
dec.UseNumber() // required for CPS float/int distinction

var raw map[string]any
dec.Decode(&raw)

sealed := capsule.ExtractSealed(raw)
// sealed.Content has seal fields removed
// sealed.Hash, sealed.Signature, sealed.SignedBy populated
```

## Conformance

This library passes all 16 golden test vectors from the CPS conformance suite:

| Fixture | Tests |
|---|---|
| minimal | Defaults, float 0.0, nulls |
| full | All sections, nested options, tool calls, metrics |
| kill_switch | Kill type, blocked status |
| tool_invocation | Tool type with tool call |
| chat_interaction | Chat type with session |
| workflow_hierarchy | Parent-child linking |
| unicode_strings | French, Japanese, emoji (UTF-8) |
| fractional_timestamp | Microsecond precision |
| empty_vs_null | Empty string vs null distinction |
| confidence_one | 1.0 as float, not integer |
| deep_nesting | Recursive key sorting |
| chain_genesis | Sequence 0, null previous_hash |
| chain_linked | Sequence 1, hash linkage |
| failure_with_error | Error paths |
| auth_escalated | MFA escalation chain |
| vault_secret | Secret rotation, policy authority |

```bash
go test -v ./...
```

## CPS Compliance

Implements CPS Section 2 (canonical JSON), Section 3.1 (SHA3-256), Section 3.2 (Ed25519 verification), Section 3.4 (verification algorithm), and Section 4 (chain rules).

Does **not** implement capsule creation or sealing (verification only).

## Dependencies

- `golang.org/x/crypto/sha3` -- SHA3-256 (FIPS 202)
- `crypto/ed25519` -- Ed25519 (stdlib, FIPS 186-5)

## License

Apache-2.0. See the [Capsule Protocol](https://github.com/quantumpipes/capsule) for specification and patent grant.

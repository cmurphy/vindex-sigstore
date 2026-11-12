// Copyright 2026 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package identity implements the Rekor PQC (c2sp.org/identity-transparency
// version 0x01 / identity v0.0.1) leaf mapping logic and client canonical key
// formatting helpers.
//
// Version 0x01 binary leaf layout:
//
//	0x01 || H(root_of_trust) || H(message) || [H(H(key)) || H(H(value))]* || H(receipt)
//
// Each digest is a 32-byte SHA-256 hash. No normalization is applied to
// identity, claim, or issuer strings before hashing.
package identity

import (
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/sigstore/vindex-sigstore/pkg/mapper/claim"
)

const (
	// LeafVersionV1 is the leading version byte for c2sp.org/identity-transparency v1 leaves.
	LeafVersionV1 byte = 0x01

	hashSize   = sha256.Size // 32 bytes
	kvPairSize = 2 * hashSize // 64 bytes: H(H(key)) || H(H(value))
	// minLeafSize = 1 (version) + 32 (root_of_trust) + 32 (message) + 32 (receipt) = 97 bytes.
	minLeafSize = 1 + 3*hashSize

	// Standard OIDC key-value pair names in identity v0.0.1 leaves.
	ClaimIdentity = "identity"
	ClaimIssuer   = "issuer"

	// Public key algorithm identifiers prefixed to SPKI DER in root_of_trust.
	AlgMLDSA44 = "ML-DSA-44"
	AlgMLDSA65 = "ML-DSA-65"
	AlgMLDSA87 = "ML-DSA-87"
	AlgEd25519 = "Ed25519"
)

var (
	// Precomputed H(H(name)) digests for O(1) binary leaf inspection without runtime hashing.
	keyHashIdentity [hashSize]byte
	keyHashIssuer   [hashSize]byte
	allowlistedKH   map[[hashSize]byte]struct{}

	// SPKI AlgorithmIdentifier OIDs (RFC 9881 for ML-DSA, RFC 8410 for Ed25519).
	oidMLDSA44 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17}
	oidMLDSA65 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}
	oidMLDSA87 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 19}
	oidEd25519 = asn1.ObjectIdentifier{1, 3, 101, 112}
)

func init() {
	keyHashIdentity = DoubleSHA256([]byte(ClaimIdentity))
	keyHashIssuer = DoubleSHA256([]byte(ClaimIssuer))
	allowlistedKH = make(map[[hashSize]byte]struct{}, len(claim.Allowlisted))
	for _, c := range claim.Allowlisted {
		allowlistedKH[DoubleSHA256([]byte(c.Name))] = struct{}{}
	}
}

// DoubleSHA256 returns SHA256(SHA256(b)).
func DoubleSHA256(b []byte) [hashSize]byte {
	first := sha256.Sum256(b)
	return sha256.Sum256(first[:])
}

// DoubleSHA256Hex returns the 64-character lowercase hex encoding of SHA256(SHA256([]byte(s))).
func DoubleSHA256Hex(s string) string {
	d := DoubleSHA256([]byte(s))
	return hex.EncodeToString(d[:])
}

// FormatIdentityKey formats an exact OIDC identity lookup key for an identity v0.0.1 shard:
//
//	hex(SHA256(SHA256(identityVal))):hex(SHA256(SHA256(issuer)))
func FormatIdentityKey(identityVal, issuer string) string {
	return DoubleSHA256Hex(identityVal) + ":" + DoubleSHA256Hex(issuer)
}

// FormatIdentityPrefix formats an any-issuer OIDC identity prefix lookup key:
//
//	hex(SHA256(SHA256(identityVal))):
func FormatIdentityPrefix(identityVal string) string {
	return DoubleSHA256Hex(identityVal) + ":"
}

// FormatClaimKey formats an exact OIDC claim lookup key for an identity v0.0.1 shard:
//
//	hex(SHA256(SHA256(claimName))):hex(SHA256(SHA256(value))):hex(SHA256(SHA256(issuer)))
func FormatClaimKey(claimName, value, issuer string) string {
	return DoubleSHA256Hex(claimName) + ":" + DoubleSHA256Hex(value) + ":" + DoubleSHA256Hex(issuer)
}

// FormatClaimPrefix formats an any-issuer OIDC claim prefix lookup key:
//
//	hex(SHA256(SHA256(claimName))):hex(SHA256(SHA256(value))):
func FormatClaimPrefix(claimName, value string) string {
	return DoubleSHA256Hex(claimName) + ":" + DoubleSHA256Hex(value) + ":"
}

type spkiHeader struct {
	Algorithm struct {
		Algorithm  asn1.ObjectIdentifier
		Parameters asn1.RawValue `asn1:"optional"`
	}
	SubjectPublicKey asn1.BitString
}

// PublicKeyAlgorithmFromSPKI extracts the identity-transparency algorithm prefix
// ("ML-DSA-44", "ML-DSA-65", "ML-DSA-87", or "Ed25519") from DER-encoded SPKI bytes.
func PublicKeyAlgorithmFromSPKI(spkiDER []byte) (string, error) {
	if len(spkiDER) == 0 {
		return "", errors.New("empty SPKI DER public key")
	}
	var spki spkiHeader
	rest, err := asn1.Unmarshal(spkiDER, &spki)
	if err != nil {
		return "", fmt.Errorf("failed to parse SPKI DER: %w", err)
	}
	if len(rest) != 0 {
		return "", errors.New("trailing bytes after SPKI DER")
	}
	oid := spki.Algorithm.Algorithm
	switch {
	case oid.Equal(oidMLDSA44):
		return AlgMLDSA44, nil
	case oid.Equal(oidMLDSA65):
		return AlgMLDSA65, nil
	case oid.Equal(oidMLDSA87):
		return AlgMLDSA87, nil
	case oid.Equal(oidEd25519):
		return AlgEd25519, nil
	default:
		return "", fmt.Errorf("unsupported SPKI public key algorithm OID %s", oid.String())
	}
}

// PublicKeyFingerprintWithAlg computes hex(SHA256(alg || spkiDER)), matching the
// root_of_trust digest stored in identity v0.0.1 managed public key leaves.
func PublicKeyFingerprintWithAlg(alg string, spkiDER []byte) string {
	h := sha256.New()
	h.Write([]byte(alg))
	h.Write(spkiDER)
	var sum [hashSize]byte
	h.Sum(sum[:0])
	return hex.EncodeToString(sum[:])
}

// PublicKeyFingerprint parses the SPKI AlgorithmIdentifier from spkiDER and returns
// hex(SHA256("<algorithm>" || spkiDER)) for querying identity v0.0.1 shards.
func PublicKeyFingerprint(spkiDER []byte) (string, error) {
	alg, err := PublicKeyAlgorithmFromSPKI(spkiDER)
	if err != nil {
		return "", err
	}
	return PublicKeyFingerprintWithAlg(alg, spkiDER), nil
}

func formatTwoDigests(d1, d2 [hashSize]byte) string {
	var buf [2*hashSize + 1 + 2*hashSize]byte // 129 bytes
	hex.Encode(buf[0:64], d1[:])
	buf[64] = ':'
	hex.Encode(buf[65:129], d2[:])
	return string(buf[:])
}

func formatThreeDigests(d1, d2, d3 [hashSize]byte) string {
	var buf [2*hashSize + 1 + 2*hashSize + 1 + 2*hashSize]byte // 194 bytes
	hex.Encode(buf[0:64], d1[:])
	buf[64] = ':'
	hex.Encode(buf[65:129], d2[:])
	buf[129] = ':'
	hex.Encode(buf[130:194], d3[:])
	return string(buf[:])
}

type kvPair struct {
	keyHash [hashSize]byte
	valHash [hashSize]byte
}

// MapLeaf inspects a Rekor PQC (identity v0.0.1 / c2sp.org/identity-transparency v1)
// binary leaf and emits canonical lowercase-hex keys:
//
//   - OIDC entry (both "identity" and "issuer" KV pairs present):
//     1. Identity:  hex(VH[identity]):hex(VH[issuer])
//     2. Claims:    hex(KH[claim]):hex(VH[claim]):hex(VH[issuer]) for the 6 allowlisted claims
//   - Managed public key entry (neither "identity" nor "issuer" KV pair present):
//     1. PublicKey: hex(root_of_trust)
func MapLeaf(leaf []byte, rawEmit func(key []byte)) {
	if len(leaf) < minLeafSize || leaf[0] != LeafVersionV1 || (len(leaf)-minLeafSize)%kvPairSize != 0 {
		return
	}

	rootOfTrust := leaf[1 : 1+hashSize]
	kvSection := leaf[1+2*hashSize : len(leaf)-hashSize]

	var (
		hasIdentity bool
		hasIssuer   bool
		issuerVH    [hashSize]byte
		identities  [][hashSize]byte
		claims      []kvPair
	)

	for off := 0; off < len(kvSection); off += kvPairSize {
		var kh, vh [hashSize]byte
		copy(kh[:], kvSection[off:off+hashSize])
		copy(vh[:], kvSection[off+hashSize:off+kvPairSize])

		switch {
		case kh == keyHashIdentity:
			hasIdentity = true
			identities = append(identities, vh)
		case kh == keyHashIssuer:
			if !hasIssuer {
				hasIssuer = true
				issuerVH = vh
			}
		default:
			if _, ok := allowlistedKH[kh]; ok {
				claims = append(claims, kvPair{keyHash: kh, valHash: vh})
			}
		}
	}

	// Managed public key entry: neither "identity" nor "issuer" KV pair is present.
	if !hasIdentity && !hasIssuer {
		var hexRoot [2 * hashSize]byte
		hex.Encode(hexRoot[:], rootOfTrust)
		rawEmit(hexRoot[:])
		return
	}

	// Partial/malformed OIDC entry (missing either "identity" or "issuer"): do not emit
	// root_of_trust (which for OIDC is H(issuer)) and cannot form "<digest>:<issuer_digest>".
	if !hasIdentity || !hasIssuer {
		return
	}

	seen := make(map[string]struct{}, len(identities)+len(claims))
	emit := func(k string) {
		if _, exists := seen[k]; exists {
			return
		}
		seen[k] = struct{}{}
		rawEmit([]byte(k))
	}

	for _, idVH := range identities {
		emit(formatTwoDigests(idVH, issuerVH))
	}
	for _, c := range claims {
		emit(formatThreeDigests(c.keyHash, c.valHash, issuerVH))
	}
}

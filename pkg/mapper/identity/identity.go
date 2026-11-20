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
// version 0x01 / identity v0.0.1) leaf mapping logic.
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
	"encoding/hex"

	"github.com/sigstore/vindex-sigstore/pkg/mapper/claim"
)

const (
	// LeafVersionV1 is the leading version byte for c2sp.org/identity-transparency v1 leaves.
	LeafVersionV1 byte = 0x01

	hashSize   = sha256.Size  // 32 bytes
	kvPairSize = 2 * hashSize // 64 bytes: H(H(key)) || H(H(value))
	// minLeafSize = 1 (version) + 32 (root_of_trust) + 32 (message) + 32 (receipt) = 97 bytes.
	minLeafSize = 1 + 3*hashSize

	// Standard OIDC key-value pair names in identity v0.0.1 leaves.
	ClaimIdentity = "identity"
	ClaimIssuer   = "issuer"
)

var (
	// Precomputed H(H(name)) digests for O(1) binary leaf inspection without runtime hashing.
	keyHashIdentity [hashSize]byte
	keyHashIssuer   [hashSize]byte
	allowlistedKH   map[[hashSize]byte]struct{}
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
//
// A key may be emitted more than once for one leaf; the VIndex host discards
// the duplicates.
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

	for _, idVH := range identities {
		rawEmit([]byte(formatTwoDigests(idVH, issuerVH)))
	}
	for _, c := range claims {
		rawEmit([]byte(formatThreeDigests(c.keyHash, c.valHash, issuerVH)))
	}
}

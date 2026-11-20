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

// Package hashedrekord implements the Rekor v2 (hashedrekord v0.0.2) Identity
// Monitor leaf mapping logic.
//
// Values are indexed without normalization (such as lowercasing or
// whitespace trimming):
//   - Email SANs are used as they appear in the certificate.
//   - URI SANs are re-serialized by net/url, which may percent-encode
//     characters that appear literally in the certificate (for example '|').
//   - Fulcio extension values are the contents of their DER UTF8String or
//     OCTET STRING. The v1 issuer extension is used as raw bytes.
//   - Public keys are indexed by the hex SHA-256 of their DER encoding.
//
// Bytes outside printable non-whitespace ASCII (0x21..0x7E) are
// percent-encoded in the key (see PercentEncode), so clients must encode the
// keys and prefixes they query the same way. A key that is empty, or longer
// than 1024 bytes after encoding, is not indexed.
package hashedrekord

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"

	"github.com/sigstore/vindex-sigstore/pkg/mapper/claim"
)

// HashedRekordEntry represents the subset of a Rekor v2 hashedrekord v0.0.2
// JSON leaf required to extract signing identities and public keys.
type HashedRekordEntry struct {
	Spec struct {
		HashedRekordV002 struct {
			Signature struct {
				Verifier struct {
					X509Certificate *struct {
						RawBytes string `json:"rawBytes"`
					} `json:"x509Certificate,omitempty"`
					PublicKey *struct {
						RawBytes string `json:"rawBytes"`
					} `json:"publicKey,omitempty"`
				} `json:"verifier"`
			} `json:"signature"`
		} `json:"hashedRekordV002"`
	} `json:"spec"`
}

var (
	// Fulcio OIDC Issuer OIDs:
	// - 1.3.6.1.4.1.57264.1.1 (v1: raw ASCII bytes)
	// - 1.3.6.1.4.1.57264.1.8 (v2: ASN.1 DER UTF8String or OCTET STRING)
	oidIssuerV1 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1}
	oidIssuerV2 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 8}
)

// FormatKeyWithIssuer formats an identity or extension key coupled with its OIDC issuer.
// It always includes the ':' delimiter (even if issuer is empty) so that issuer-unscoped
// lookups can query "<baseKey>:" as a prefix without matching sibling prefixes.
func FormatKeyWithIssuer(baseKey, issuer string) string {
	return baseKey + ":" + issuer
}

// FormatExtensionKey formats a Fulcio extension's claim name (for example
// "source-repository-uri") and its extension value.
func FormatExtensionKey(claimName, value string) string {
	return claimName + ":" + value
}

// PublicKeyFingerprint computes the lowercase hex-encoded SHA-256 digest of DER-encoded PKIX public key bytes.
func PublicKeyFingerprint(keyDER []byte) string {
	sum := sha256.Sum256(keyDER)
	return hex.EncodeToString(sum[:])
}

// parseExtensionString returns the string held in a DER-encoded extension
// value, which is a UTF8String or an OCTET STRING.
func parseExtensionString(val []byte) (string, error) {
	var str string
	if _, err := asn1.Unmarshal(val, &str); err != nil {
		var octets []byte
		if _, err := asn1.Unmarshal(val, &octets); err == nil {
			return string(octets), nil
		}
		return "", err
	}
	return str, nil
}

func extractIssuer(cert *x509.Certificate) string {
	var issuer string
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidIssuerV2) {
			if val, err := parseExtensionString(ext.Value); err == nil && val != "" {
				return val
			}
		} else if ext.Id.Equal(oidIssuerV1) && issuer == "" {
			// The v1 issuer extension holds the issuer as raw bytes, not DER.
			issuer = string(ext.Value)
		}
	}
	return issuer
}

// claimNameForOID returns the claim name of an allowlisted Fulcio extension.
// Keys identify an extension by its claim name rather than its OID.
func claimNameForOID(id asn1.ObjectIdentifier) (string, bool) {
	for _, c := range claim.Allowlisted {
		if id.Equal(c.FulcioOID) {
			return c.Name, true
		}
	}
	return "", false
}

// PercentEncode replaces every byte of s outside printable non-whitespace
// ASCII (0x21..0x7E) with "%XX", using uppercase hex digits. Bytes inside the
// range, including '%', are left unchanged.
//
// MapLeaf applies it to every key it emits. Because it works byte by byte,
// encoding a byte prefix of a value gives a prefix of the encoded value.
func PercentEncode(s string) string {
	const hexDigits = "0123456789ABCDEF"
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7E {
			n++
		}
	}
	if n == 0 {
		return s
	}
	buf := make([]byte, 0, len(s)+2*n)
	for i := 0; i < len(s); i++ {
		if b := s[i]; b < 0x21 || b > 0x7E {
			buf = append(buf, '%', hexDigits[b>>4], hexDigits[b&0x0F])
		} else {
			buf = append(buf, b)
		}
	}
	return string(buf)
}

// IsValidPreimageKey reports whether key satisfies VIndex's canonical key invariants:
// 1 <= len(key) <= 1024 and strictly printable non-whitespace ASCII (0x21..0x7E).
func IsValidPreimageKey(key string) bool {
	if len(key) == 0 || len(key) > 1024 {
		return false
	}
	for i := 0; i < len(key); i++ {
		b := key[i]
		if b < 0x21 || b > 0x7E {
			return false
		}
	}
	return true
}

// MapLeaf inspects a Rekor v2 JSON leaf and emits canonical search key preimages.
// A key may be emitted more than once for one leaf; the VIndex host discards
// the duplicates.
func MapLeaf(leaf []byte, rawEmit func(key []byte)) {
	emit := func(key string) {
		key = PercentEncode(key)
		if !IsValidPreimageKey(key) {
			return
		}
		rawEmit([]byte(key))
	}

	var entry HashedRekordEntry
	if err := json.Unmarshal(leaf, &entry); err != nil {
		return
	}
	verifier := entry.Spec.HashedRekordV002.Signature.Verifier
	if verifier.X509Certificate != nil {
		mapCertificate(verifier.X509Certificate.RawBytes, emit)
	}
	if verifier.PublicKey != nil {
		mapPublicKey(verifier.PublicKey.RawBytes, emit)
	}
}

// mapCertificate emits "<value>:<issuer>" keys for a base64-encoded Fulcio
// X.509 certificate. Unscoped (any-issuer) or partial-URI lookups are served
// via MPT prefix queries (/keys?prefix=).
func mapCertificate(rawBytes string, emit func(key string)) {
	certDER, err := base64.StdEncoding.DecodeString(rawBytes)
	if err != nil {
		return
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return
	}
	issuer := extractIssuer(cert)

	// Human identities (Email SAN)
	for _, email := range cert.EmailAddresses {
		if email != "" {
			emit(FormatKeyWithIssuer(email, issuer))
		}
	}

	// Workflow identities (URI SAN)
	for _, u := range cert.URIs {
		if san := u.String(); san != "" {
			emit(FormatKeyWithIssuer(san, issuer))
		}
	}

	// Allowlisted Fulcio Workload/Repository extensions, keyed by claim name
	for _, ext := range cert.Extensions {
		claimName, ok := claimNameForOID(ext.Id)
		if !ok {
			continue
		}
		val, err := parseExtensionString(ext.Value)
		if err != nil || val == "" {
			continue
		}
		emit(FormatKeyWithIssuer(FormatExtensionKey(claimName, val), issuer))
	}
}

// mapPublicKey emits the hex SHA-256 fingerprint of a base64-encoded SPKI DER
// public key.
func mapPublicKey(rawBytes string, emit func(key string)) {
	keyDER, err := base64.StdEncoding.DecodeString(rawBytes)
	if err != nil || len(keyDER) == 0 {
		return
	}
	emit(PublicKeyFingerprint(keyDER))
}

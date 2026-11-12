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
// Monitor leaf mapping logic and canonical key formatting functions shared
// between the WASM MapFn, proxy services, and clients.
//
// Values are indexed exactly as they appear in the certificate. No
// normalization (such as lowercasing or whitespace trimming) is applied, so
// clients must query with the exact value. Values that would produce an
// invalid VIndex key (for example, because they contain whitespace) are not
// indexed.
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

// FormatSubjectPrefix returns the trailing-colon prefix ("<baseKey>:") used to query
// all issuers for an exact subject or extension key via GET /keys?prefix=<prefix>.
func FormatSubjectPrefix(baseKey string) string {
	return baseKey + ":"
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

func parseExtensionString(val []byte, isV1 bool) (string, error) {
	if isV1 {
		return string(val), nil
	}
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
			if val, err := parseExtensionString(ext.Value, false); err == nil && val != "" {
				return val
			}
		} else if ext.Id.Equal(oidIssuerV1) && issuer == "" {
			if val, err := parseExtensionString(ext.Value, true); err == nil && val != "" {
				issuer = val
			}
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
func MapLeaf(leaf []byte, rawEmit func(key []byte)) {
	seen := make(map[string]struct{})
	emit := func(key string) {
		if !IsValidPreimageKey(key) {
			return
		}
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		rawEmit([]byte(key))
	}

	var entry HashedRekordEntry
	if err := json.Unmarshal(leaf, &entry); err != nil {
		return
	}
	verifier := entry.Spec.HashedRekordV002.Signature.Verifier

	// 1. Fulcio X.509 Certificate: Emit "<value>:<issuer>" keys.
	// Unscoped (any-issuer) or partial-URI lookups are served via MPT prefix queries (/keys?prefix=).
	if verifier.X509Certificate != nil && verifier.X509Certificate.RawBytes != "" {
		certDer, err := base64.StdEncoding.DecodeString(verifier.X509Certificate.RawBytes)
		if err == nil {
			if cert, err := x509.ParseCertificate(certDer); err == nil {
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
					if claimName, ok := claimNameForOID(ext.Id); ok {
						if val, err := parseExtensionString(ext.Value, false); err == nil && val != "" {
							emit(FormatKeyWithIssuer(FormatExtensionKey(claimName, val), issuer))
						}
					}
				}
			}
		}
	}

	// 2. Public Key Verifier: Emit hex SHA-256 fingerprint of SPKI DER bytes
	if verifier.PublicKey != nil && verifier.PublicKey.RawBytes != "" {
		keyDer, err := base64.StdEncoding.DecodeString(verifier.PublicKey.RawBytes)
		if err == nil && len(keyDer) > 0 {
			emit(PublicKeyFingerprint(keyDer))
		}
	}
}

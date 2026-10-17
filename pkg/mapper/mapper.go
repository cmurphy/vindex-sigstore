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

// Package mapper implements the Rekor v2 Identity Monitor leaf mapping logic
// and canonical key normalization functions shared between the WASM MapFn,
// proxy services, and clients.
package mapper

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
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
	// - 1.3.6.1.4.1.57264.1.8 (v2: ASN.1 DER UTF8String)
	oidIssuerV1 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1}
	oidIssuerV2 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 8}

	// Allowlisted Fulcio workload/repository identity OIDs:
	// - .1.9:  Build Signer URI
	// - .1.12: Source Repository URI
	// - .1.15: Source Repository Identifier
	// - .1.16: Source Repository Owner URI
	// - .1.17: Source Repository Owner Identifier
	// - .1.18: Build Config URI
	allowlistedFulcioOIDs = []asn1.ObjectIdentifier{
		{1, 3, 6, 1, 4, 1, 57264, 1, 9},
		{1, 3, 6, 1, 4, 1, 57264, 1, 12},
		{1, 3, 6, 1, 4, 1, 57264, 1, 15},
		{1, 3, 6, 1, 4, 1, 57264, 1, 16},
		{1, 3, 6, 1, 4, 1, 57264, 1, 17},
		{1, 3, 6, 1, 4, 1, 57264, 1, 18},
	}
)

// NormalizeEmail canonicalizes an email SAN by trimming whitespace and lowercasing.
func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// NormalizeURI canonicalizes a URI SAN by trimming surrounding whitespace.
func NormalizeURI(uri string) string {
	return strings.TrimSpace(uri)
}

// NormalizeIssuer canonicalizes an OIDC issuer URL by trimming whitespace and lowercasing.
func NormalizeIssuer(issuer string) string {
	return strings.ToLower(strings.TrimSpace(issuer))
}

// FormatKeyWithIssuer formats an identity or OID key coupled with a normalized OIDC issuer.
func FormatKeyWithIssuer(baseKey, issuer string) string {
	normIssuer := NormalizeIssuer(issuer)
	if normIssuer == "" {
		return baseKey
	}
	return baseKey + ":" + normIssuer
}

// FormatOIDKey formats an ASN.1 OID dot-string and its extension value.
func FormatOIDKey(oid, value string) string {
	return strings.TrimSpace(oid) + ":" + strings.TrimSpace(value)
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
				return NormalizeIssuer(val)
			}
		} else if ext.Id.Equal(oidIssuerV1) && issuer == "" {
			if val, err := parseExtensionString(ext.Value, true); err == nil && val != "" {
				issuer = NormalizeIssuer(val)
			}
		}
	}
	return issuer
}

func isAllowlistedOID(id asn1.ObjectIdentifier) bool {
	for _, allowed := range allowlistedFulcioOIDs {
		if id.Equal(allowed) {
			return true
		}
	}
	return false
}

// MapLeaf inspects a Rekor v2 JSON leaf and emits canonical search key preimages.
func MapLeaf(leaf []byte, emit func(key []byte)) {
	var entry HashedRekordEntry
	if err := json.Unmarshal(leaf, &entry); err != nil {
		return
	}
	verifier := entry.Spec.HashedRekordV002.Signature.Verifier

	// 1. Fulcio X.509 Certificate: Emit both unscoped and "<value>:<issuer>" keys
	if verifier.X509Certificate != nil && verifier.X509Certificate.RawBytes != "" {
		certDer, err := base64.StdEncoding.DecodeString(verifier.X509Certificate.RawBytes)
		if err == nil {
			if cert, err := x509.ParseCertificate(certDer); err == nil {
				issuer := extractIssuer(cert)

				// Human identities (Email SAN)
				for _, email := range cert.EmailAddresses {
					san := NormalizeEmail(email)
					if san != "" {
						emit([]byte(san))
						if issuer != "" {
							emit([]byte(FormatKeyWithIssuer(san, issuer)))
						}
					}
				}

				// Workflow identities (URI SAN)
				for _, u := range cert.URIs {
					san := NormalizeURI(u.String())
					if san != "" {
						emit([]byte(san))
						if issuer != "" {
							emit([]byte(FormatKeyWithIssuer(san, issuer)))
						}
					}
				}

				// Allowlisted Fulcio Workload/Repository OIDs
				for _, ext := range cert.Extensions {
					if isAllowlistedOID(ext.Id) {
						if val, err := parseExtensionString(ext.Value, false); err == nil {
							val = strings.TrimSpace(val)
							if val != "" {
								oidKey := FormatOIDKey(ext.Id.String(), val)
								emit([]byte(oidKey))
								if issuer != "" {
									emit([]byte(FormatKeyWithIssuer(oidKey, issuer)))
								}
							}
						}
					}
				}
			}
		}
	}

	// 2. Public Key Verifier: Emit both raw SPKI DER bytes and hex SHA-256 fingerprint
	if verifier.PublicKey != nil && verifier.PublicKey.RawBytes != "" {
		keyDer, err := base64.StdEncoding.DecodeString(verifier.PublicKey.RawBytes)
		if err == nil && len(keyDer) > 0 {
			emit(keyDer)
			emit([]byte(PublicKeyFingerprint(keyDer)))
		}
	}
}

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

package hashedrekord

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestMapLeafCertificate(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	uriSAN, err := url.Parse("https://github.com/sigstore/rekor-tiles/.github/workflows/release.yml@refs/tags/v1.0.0")
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}

	marshalUTF8 := func(val string) []byte {
		b, err := asn1.Marshal(val)
		if err != nil {
			t.Fatalf("asn1.Marshal(%q): %v", val, err)
		}
		return b
	}

	issuerBytes := marshalUTF8("https://token.actions.githubusercontent.com")
	buildSignerURIBytes := marshalUTF8("https://github.com/sigstore/rekor-tiles/.github/workflows/release.yml@refs/tags/v1.0.0")
	repoURIBytes := marshalUTF8("https://github.com/sigstore/rekor-tiles")
	repoIDBytes := marshalUTF8("890123456")
	ownerURIBytes := marshalUTF8("https://github.com/sigstore")
	ownerIDBytes := marshalUTF8("71096353")
	buildConfigURIBytes := marshalUTF8("https://github.com/sigstore/rekor-tiles/.github/workflows/release.yml@refs/tags/v1.0.0")

	tmpl := &x509.Certificate{
		SerialNumber:   big.NewInt(1),
		NotBefore:      time.Now().Add(-time.Hour),
		NotAfter:       time.Now().Add(time.Hour),
		EmailAddresses: []string{"Alice@Example.com", "alice@example.com"},
		URIs:           []*url.URL{uriSAN, uriSAN},
		ExtraExtensions: []pkix.Extension{
			{
				Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 8},
				Value: issuerBytes,
			},
			{
				Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 9},
				Value: buildSignerURIBytes,
			},
			{
				// Note: duplicate extensions cannot be used to exercise per-leaf
				// deduplication because crypto/x509.ParseCertificate rejects
				// certificates containing duplicate extensions. Deduplication is
				// exercised via the duplicate (case-variant) email and URI SANs above.
				Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 12},
				Value: repoURIBytes,
			},
			{
				Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 15},
				Value: repoIDBytes,
			},
			{
				Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 16},
				Value: ownerURIBytes,
			},
			{
				Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 17},
				Value: ownerIDBytes,
			},
			{
				Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 18},
				Value: buildConfigURIBytes,
			},
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}

	leafJSON := fmt.Sprintf(`{"spec":{"hashedRekordV002":{"signature":{"verifier":{"x509Certificate":{"rawBytes":%q}}}}}}`,
		base64.StdEncoding.EncodeToString(certDER))

	var got []string
	MapLeaf([]byte(leafJSON), func(key []byte) {
		got = append(got, string(key))
	})

	want := []string{
		// Case variants are distinct keys: no normalization is applied.
		"Alice@Example.com:https://token.actions.githubusercontent.com",
		"alice@example.com:https://token.actions.githubusercontent.com",
		"https://github.com/sigstore/rekor-tiles/.github/workflows/release.yml@refs/tags/v1.0.0:https://token.actions.githubusercontent.com",
		"build-signer-uri:https://github.com/sigstore/rekor-tiles/.github/workflows/release.yml@refs/tags/v1.0.0:https://token.actions.githubusercontent.com",
		"source-repository-uri:https://github.com/sigstore/rekor-tiles:https://token.actions.githubusercontent.com",
		"source-repository-identifier:890123456:https://token.actions.githubusercontent.com",
		"source-repository-owner-uri:https://github.com/sigstore:https://token.actions.githubusercontent.com",
		"source-repository-owner-identifier:71096353:https://token.actions.githubusercontent.com",
		"build-config-uri:https://github.com/sigstore/rekor-tiles/.github/workflows/release.yml@refs/tags/v1.0.0:https://token.actions.githubusercontent.com",
	}

	if !slices.Equal(got, want) {
		t.Errorf("MapLeaf() = %v, want %v", got, want)
	}

	// Verify prefix queries (/keys?prefix=) match the emitted keys as expected:
	// 1. Issuer-unscoped email lookup via FormatSubjectPrefix
	emailPrefix := FormatSubjectPrefix("alice@example.com")
	if !strings.HasPrefix(got[1], emailPrefix) {
		t.Errorf("key %q does not match subject prefix %q", got[1], emailPrefix)
	}
	if strings.HasPrefix(got[0], emailPrefix) {
		t.Errorf("key %q unexpectedly matches case-different subject prefix %q", got[0], emailPrefix)
	}
	// 2. Workflow path without git ref (all tags/branches)
	workflowPrefix := "https://github.com/sigstore/rekor-tiles/.github/workflows/release.yml@"
	if !strings.HasPrefix(got[2], workflowPrefix) {
		t.Errorf("key %q does not match workflow prefix %q", got[2], workflowPrefix)
	}
	// 3. Repo prefix on URI SAN
	repoURIPrefix := "https://github.com/sigstore/rekor-tiles/"
	if !strings.HasPrefix(got[2], repoURIPrefix) {
		t.Errorf("key %q does not match repo URI prefix %q", got[2], repoURIPrefix)
	}
	// 4. Issuer-unscoped extension lookup via FormatSubjectPrefix
	extPrefix := FormatSubjectPrefix(FormatExtensionKey("source-repository-uri", "https://github.com/sigstore/rekor-tiles"))
	if !strings.HasPrefix(got[4], extPrefix) {
		t.Errorf("key %q does not match extension prefix %q", got[4], extPrefix)
	}
}

func TestMapLeafPercentEncoding(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	marshalUTF8 := func(val string) []byte {
		b, err := asn1.Marshal(val)
		if err != nil {
			t.Fatalf("asn1.Marshal(%q): %v", val, err)
		}
		return b
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		// Whitespace inside a SAN is encoded.
		EmailAddresses: []string{"alice@example.com", "alice smith@example.com"},
		ExtraExtensions: []pkix.Extension{
			{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 8}, Value: marshalUTF8("https://accounts.google.com")},
			// A literal '%' is inside the printable range and is left as is.
			{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 9}, Value: marshalUTF8("https://example.com/100%")},
			// Non-ASCII characters are encoded one UTF-8 byte at a time.
			{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 12}, Value: marshalUTF8("https://github.com/org/répo")},
			// Surrounding whitespace is not trimmed; it is encoded.
			{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 15}, Value: marshalUTF8(" 890123456 ")},
			// A key longer than 1024 bytes after encoding is dropped.
			{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 16}, Value: marshalUTF8(strings.Repeat(" ", 400))},
		},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	leafJSON := fmt.Sprintf(`{"spec":{"hashedRekordV002":{"signature":{"verifier":{"x509Certificate":{"rawBytes":%q}}}}}}`,
		base64.StdEncoding.EncodeToString(certDER))

	var got []string
	MapLeaf([]byte(leafJSON), func(key []byte) {
		got = append(got, string(key))
	})
	want := []string{
		"alice@example.com:https://accounts.google.com",
		"alice%20smith@example.com:https://accounts.google.com",
		"build-signer-uri:https://example.com/100%:https://accounts.google.com",
		"source-repository-uri:https://github.com/org/r%C3%A9po:https://accounts.google.com",
		"source-repository-identifier:%20890123456%20:https://accounts.google.com",
	}
	if !slices.Equal(got, want) {
		t.Errorf("MapLeaf() = %q, want %q", got, want)
	}
	for _, k := range got {
		if !IsValidPreimageKey(k) {
			t.Errorf("emitted key %q is not a valid VIndex key", k)
		}
	}
}

func TestPercentEncode(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"", ""},
		{"alice@example.com", "alice@example.com"},
		{"a b", "a%20b"},
		{"\t\r\n", "%09%0D%0A"},
		{"é", "%C3%A9"},
		{"\x00\x7f\xff", "%00%7F%FF"},
		{"!~", "!~"},
		{"100%", "100%"},
		{"a%20b", "a%20b"},
	} {
		if got := PercentEncode(tc.in); got != tc.want {
			t.Errorf("PercentEncode(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	// Encoding a byte prefix of a value gives a prefix of the encoded value,
	// even when the prefix ends inside a multi-byte character.
	value := "https://github.com/org/répo"
	for i := 0; i <= len(value); i++ {
		if p := PercentEncode(value[:i]); !strings.HasPrefix(PercentEncode(value), p) {
			t.Errorf("PercentEncode(%q) = %q is not a prefix of the encoded value", value[:i], p)
		}
	}
}

func TestMapLeafPublicKey(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	spkiDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}

	leafJSON := fmt.Sprintf(`{"spec":{"hashedRekordV002":{"signature":{"verifier":{"publicKey":{"rawBytes":%q}}}}}}`,
		base64.StdEncoding.EncodeToString(spkiDER))

	var got [][]byte
	MapLeaf([]byte(leafJSON), func(key []byte) {
		got = append(got, slices.Clone(key))
	})

	if len(got) != 1 {
		t.Fatalf("expected 1 emitted key, got %d", len(got))
	}
	wantFP := PublicKeyFingerprint(spkiDER)
	if string(got[0]) != wantFP {
		t.Errorf("emitted key = %q, want %q", string(got[0]), wantFP)
	}
	if !IsValidPreimageKey(string(got[0])) {
		t.Errorf("emitted key %q is not a valid printable ASCII preimage key", string(got[0]))
	}
}

func TestIsValidPreimageKey(t *testing.T) {
	if !IsValidPreimageKey("alice@example.com:https://accounts.google.com") {
		t.Error("expected valid printable ASCII key to pass")
	}
	if IsValidPreimageKey("") {
		t.Error("expected empty key to fail")
	}
	if IsValidPreimageKey("has space") {
		t.Error("expected key with space (0x20) to fail")
	}
	if IsValidPreimageKey(string([]byte{0x30, 0x59, 0x30, 0x13})) {
		t.Error("expected raw ASN.1 DER bytes containing 0x13 to fail")
	}
}

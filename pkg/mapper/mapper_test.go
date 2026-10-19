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

package mapper

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

	issuerBytes, err := asn1.Marshal("https://token.actions.githubusercontent.com")
	if err != nil {
		t.Fatalf("asn1.Marshal issuer: %v", err)
	}
	repoBytes, err := asn1.Marshal("https://github.com/sigstore/rekor-tiles")
	if err != nil {
		t.Fatalf("asn1.Marshal repo: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:   big.NewInt(1),
		NotBefore:      time.Now().Add(-time.Hour),
		NotAfter:       time.Now().Add(time.Hour),
		EmailAddresses: []string{"Alice@Example.com"},
		URIs:           []*url.URL{uriSAN},
		ExtraExtensions: []pkix.Extension{
			{
				Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 8},
				Value: issuerBytes,
			},
			{
				Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 12},
				Value: repoBytes,
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
		"alice@example.com:https://token.actions.githubusercontent.com",
		"https://github.com/sigstore/rekor-tiles/.github/workflows/release.yml@refs/tags/v1.0.0:https://token.actions.githubusercontent.com",
		"1.3.6.1.4.1.57264.1.12:https://github.com/sigstore/rekor-tiles:https://token.actions.githubusercontent.com",
	}

	if !slices.Equal(got, want) {
		t.Errorf("MapLeaf() = %v, want %v", got, want)
	}

	// Verify prefix queries (?prefix=true) match the emitted keys as expected:
	// 1. Issuer-unscoped email lookup via FormatSubjectPrefix
	emailPrefix := FormatSubjectPrefix(NormalizeEmail("Alice@Example.com"))
	if !strings.HasPrefix(got[0], emailPrefix) {
		t.Errorf("key %q does not match subject prefix %q", got[0], emailPrefix)
	}
	// 2. Workflow path without git ref (all tags/branches)
	workflowPrefix := "https://github.com/sigstore/rekor-tiles/.github/workflows/release.yml@"
	if !strings.HasPrefix(got[1], workflowPrefix) {
		t.Errorf("key %q does not match workflow prefix %q", got[1], workflowPrefix)
	}
	// 3. Repo prefix on URI SAN
	repoURIPrefix := "https://github.com/sigstore/rekor-tiles/"
	if !strings.HasPrefix(got[1], repoURIPrefix) {
		t.Errorf("key %q does not match repo URI prefix %q", got[1], repoURIPrefix)
	}
	// 4. Issuer-unscoped OID lookup via FormatSubjectPrefix
	oidPrefix := FormatSubjectPrefix(FormatOIDKey("1.3.6.1.4.1.57264.1.12", "https://github.com/sigstore/rekor-tiles"))
	if !strings.HasPrefix(got[2], oidPrefix) {
		t.Errorf("key %q does not match OID prefix %q", got[2], oidPrefix)
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

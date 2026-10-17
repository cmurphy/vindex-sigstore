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
		"alice@example.com",
		"alice@example.com:https://token.actions.githubusercontent.com",
		"https://github.com/sigstore/rekor-tiles/.github/workflows/release.yml@refs/tags/v1.0.0",
		"https://github.com/sigstore/rekor-tiles/.github/workflows/release.yml@refs/tags/v1.0.0:https://token.actions.githubusercontent.com",
		"1.3.6.1.4.1.57264.1.12:https://github.com/sigstore/rekor-tiles",
		"1.3.6.1.4.1.57264.1.12:https://github.com/sigstore/rekor-tiles:https://token.actions.githubusercontent.com",
	}

	if !slices.Equal(got, want) {
		t.Errorf("MapLeaf() = %v, want %v", got, want)
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

	if len(got) != 2 {
		t.Fatalf("expected 2 emitted keys, got %d", len(got))
	}
	if !slices.Equal(got[0], spkiDER) {
		t.Errorf("first emitted key did not match raw SPKI DER")
	}
	wantFP := PublicKeyFingerprint(spkiDER)
	if string(got[1]) != wantFP {
		t.Errorf("second emitted key = %q, want %q", string(got[1]), wantFP)
	}
}

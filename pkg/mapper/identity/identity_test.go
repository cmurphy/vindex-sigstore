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

package identity

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"slices"
	"strings"
	"testing"

	"github.com/sigstore/vindex-sigstore/pkg/mapper/claim"
)

// h2 returns hex(SHA256(SHA256(s))), the form in which a client hashes an
// identity, claim name, claim value, or issuer to build a lookup key.
func h2(s string) string {
	d := DoubleSHA256([]byte(s))
	return hex.EncodeToString(d[:])
}

func identityKey(identityVal, issuer string) string {
	return h2(identityVal) + ":" + h2(issuer)
}

func claimKey(claimName, value, issuer string) string {
	return h2(claimName) + ":" + h2(value) + ":" + h2(issuer)
}

func isValidPreimageKey(key string) bool {
	if len(key) == 0 || len(key) > 1024 {
		return false
	}
	for i := 0; i < len(key); i++ {
		if key[i] < 0x21 || key[i] > 0x7E {
			return false
		}
	}
	return true
}

type rawKV struct {
	key string
	val string
}

// buildIdentityLeaf constructs a valid version 0x01 binary leaf with lexicographically
// sorted double-hashed key-value pairs.
func buildIdentityLeaf(rootOfTrust [32]byte, message [32]byte, pairs []rawKV, receipt [32]byte) []byte {
	type hashedKV struct {
		kh [32]byte
		vh [32]byte
	}
	hPairs := make([]hashedKV, 0, len(pairs))
	for _, p := range pairs {
		hPairs = append(hPairs, hashedKV{
			kh: DoubleSHA256([]byte(p.key)),
			vh: DoubleSHA256([]byte(p.val)),
		})
	}
	slices.SortFunc(hPairs, func(a, b hashedKV) int {
		return bytes.Compare(a.kh[:], b.kh[:])
	})

	buf := make([]byte, 0, minLeafSize+len(hPairs)*kvPairSize)
	buf = append(buf, LeafVersionV1)
	buf = append(buf, rootOfTrust[:]...)
	buf = append(buf, message[:]...)
	for _, hp := range hPairs {
		buf = append(buf, hp.kh[:]...)
		buf = append(buf, hp.vh[:]...)
	}
	buf = append(buf, receipt[:]...)
	return buf
}

func collectKeys(leaf []byte) []string {
	var out []string
	MapLeaf(leaf, func(key []byte) {
		out = append(out, string(key))
	})
	return out
}

func TestMapLeaf_OIDCHumanIdentity(t *testing.T) {
	issuer := "https://accounts.google.com"
	email := "untrusted-sa@sigstore-conformance.iam.gserviceaccount.com"
	sub := "105144618049248966177"

	rot := sha256.Sum256([]byte(issuer))
	msg := sha256.Sum256([]byte("artifact"))
	var zeroReceipt [32]byte

	leaf := buildIdentityLeaf(rot, msg, []rawKV{
		{key: "issuer", val: issuer},
		{key: "subject", val: sub},
		{key: "identity", val: email},
	}, zeroReceipt)

	got := collectKeys(leaf)
	wantKey := identityKey(email, issuer)
	if len(got) != 1 || got[0] != wantKey {
		t.Fatalf("MapLeaf(OIDC human) = %v, want [%s]", got, wantKey)
	}
	if !isValidPreimageKey(got[0]) {
		t.Errorf("emitted key %q violates VIndex canonical key contract", got[0])
	}
	if anyIssuer := h2(email) + ":"; !strings.HasPrefix(got[0], anyIssuer) {
		t.Errorf("emitted key %q does not match any-issuer prefix %q", got[0], anyIssuer)
	}
}

func TestMapLeaf_OIDCGitHubWorkflowOnlyAllowlistedClaims(t *testing.T) {
	issuer := "https://token.actions.githubusercontent.com"
	workflowURI := "https://github.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon/.github/workflows/extremely-dangerous-oidc-beacon.yml@refs/heads/main"
	repoURI := "https://github.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon"
	repoID := "451877925"
	ownerURI := "https://github.com/sigstore-conformance"
	ownerID := "100239729"
	buildConfigURI := workflowURI

	rot := sha256.Sum256([]byte(issuer))
	msg := sha256.Sum256([]byte("artifact"))
	var zeroReceipt [32]byte

	// Include all 14 GitHub Actions Fulcio claims + subject; only identity + the 6 allowlisted claims must be emitted.
	leaf := buildIdentityLeaf(rot, msg, []rawKV{
		{key: "issuer", val: issuer},
		{key: "subject", val: "repo:sigstore-conformance/extremely-dangerous-public-oidc-beacon:ref:refs/heads/main"},
		{key: "identity", val: workflowURI},
		// 6 allowlisted claims:
		{key: claim.BuildSignerURI, val: workflowURI},
		{key: claim.SourceRepositoryURI, val: repoURI},
		{key: claim.SourceRepositoryIdentifier, val: repoID},
		{key: claim.SourceRepositoryOwnerURI, val: ownerURI},
		{key: claim.SourceRepositoryOwnerIdentifier, val: ownerID},
		{key: claim.BuildConfigURI, val: buildConfigURI},
		// 8 non-allowlisted / high-cardinality claims that MUST NOT be indexed:
		{key: "build-signer-digest", val: "deadbeef1234"},
		{key: "build-config-digest", val: "deadbeef1234"},
		{key: "build-trigger", val: "schedule"},
		{key: "runner-environment", val: "github-hosted"},
		{key: "run-invocation-uri", val: repoURI + "/actions/runs/999999/attempts/1"},
		{key: "source-repository-digest", val: "deadbeef1234"},
		{key: "source-repository-ref", val: "refs/heads/main"},
		{key: "source-repository-visibility-at-signing", val: "public"},
	}, zeroReceipt)

	got := collectKeys(leaf)
	want := []string{
		identityKey(workflowURI, issuer),
		claimKey(claim.BuildSignerURI, workflowURI, issuer),
		claimKey(claim.SourceRepositoryURI, repoURI, issuer),
		claimKey(claim.SourceRepositoryIdentifier, repoID, issuer),
		claimKey(claim.SourceRepositoryOwnerURI, ownerURI, issuer),
		claimKey(claim.SourceRepositoryOwnerIdentifier, ownerID, issuer),
		claimKey(claim.BuildConfigURI, buildConfigURI, issuer),
	}

	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("MapLeaf(OIDC GitHub) mismatch:\ngot  (%d): %v\nwant (%d): %v", len(got), got, len(want), want)
	}

	for _, k := range got {
		if !isValidPreimageKey(k) {
			t.Errorf("emitted key %q violates VIndex canonical key contract", k)
		}
	}
	anyIssuer := h2(claim.SourceRepositoryURI) + ":" + h2(repoURI) + ":"
	if !slices.ContainsFunc(got, func(k string) bool { return strings.HasPrefix(k, anyIssuer) }) {
		t.Errorf("no emitted key matches any-issuer claim prefix %q", anyIssuer)
	}
}

func TestMapLeaf_NoNormalizationPreservesCase(t *testing.T) {
	upperEmail := "Alice.Upper@Example.COM"
	lowerEmail := "alice.upper@example.com"
	issuer := "https://Accounts.Google.COM"

	rot := sha256.Sum256([]byte(issuer))
	msg := sha256.Sum256([]byte("artifact"))
	var zeroReceipt [32]byte

	var got []string
	for _, email := range []string{upperEmail, lowerEmail} {
		leaf := buildIdentityLeaf(rot, msg, []rawKV{
			{key: "issuer", val: issuer},
			{key: "identity", val: email},
		}, zeroReceipt)
		keys := collectKeys(leaf)
		if want := identityKey(email, issuer); len(keys) != 1 || keys[0] != want {
			t.Fatalf("MapLeaf(%q) = %v, want [%s]", email, keys, want)
		}
		got = append(got, keys[0])
	}
	if got[0] == got[1] {
		t.Fatal("expected exact case preservation with no lowercasing normalization")
	}
}

func TestMapLeaf_ManagedPublicKey(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	spkiDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	// root_of_trust for a managed key is SHA256("<algorithm>" || SPKI DER).
	rot := sha256.Sum256(append([]byte("Ed25519"), spkiDER...))
	wantFP := hex.EncodeToString(rot[:])
	msg := sha256.Sum256([]byte("artifact"))
	sigReceipt := sha256.Sum256([]byte("signature"))

	// Without context KV pair (97-byte leaf)
	leafNoCtx := buildIdentityLeaf(rot, msg, nil, sigReceipt)
	gotNoCtx := collectKeys(leafNoCtx)
	if len(gotNoCtx) != 1 || gotNoCtx[0] != wantFP {
		t.Fatalf("MapLeaf(pubkey no context) = %v, want [%s]", gotNoCtx, wantFP)
	}

	// With context KV pair (161-byte leaf)
	leafWithCtx := buildIdentityLeaf(rot, msg, []rawKV{{key: "context", val: "sigstore"}}, sigReceipt)
	gotWithCtx := collectKeys(leafWithCtx)
	if len(gotWithCtx) != 1 || gotWithCtx[0] != wantFP {
		t.Fatalf("MapLeaf(pubkey with context) = %v, want [%s]", gotWithCtx, wantFP)
	}
}

func TestMapLeaf_RejectsInvalidAndPartialLeaves(t *testing.T) {
	var z [32]byte

	// Wrong version byte (0x02)
	badVer := buildIdentityLeaf(z, z, nil, z)
	badVer[0] = 0x02
	if got := collectKeys(badVer); len(got) != 0 {
		t.Errorf("expected 0 keys for version 0x02, got %v", got)
	}

	// Too short (< 97 bytes)
	if got := collectKeys(make([]byte, 96)); len(got) != 0 {
		t.Errorf("expected 0 keys for 96-byte leaf, got %v", got)
	}

	// Non-64-byte KV stride
	if got := collectKeys(make([]byte, 97+32)); len(got) != 0 {
		t.Errorf("expected 0 keys for misaligned KV section, got %v", got)
	}

	// Partial OIDC leaf (has "identity" without "issuer" or "issuer" without "identity"):
	// MUST NOT emit root_of_trust as a public key!
	onlyIdentity := buildIdentityLeaf(z, z, []rawKV{{key: "identity", val: "alice@example.com"}}, z)
	if got := collectKeys(onlyIdentity); len(got) != 0 {
		t.Errorf("expected 0 keys for partial OIDC leaf (identity only), got %v", got)
	}
	onlyIssuer := buildIdentityLeaf(z, z, []rawKV{{key: "issuer", val: "https://accounts.google.com"}}, z)
	if got := collectKeys(onlyIssuer); len(got) != 0 {
		t.Errorf("expected 0 keys for partial OIDC leaf (issuer only), got %v", got)
	}
}

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

// Package claim defines the CI provenance claims indexed by both the
// hashedrekord v0.0.2 and identity v0.0.1 MapFns.
//
// The hashedrekord MapFn finds a claim by the OID of its Fulcio X.509
// extension and uses the claim name in the key. The identity MapFn matches
// the double SHA-256 digest of a claim name against the claim keys in a leaf.
package claim

import "encoding/asn1"

const (
	BuildSignerURI                  = "build-signer-uri"
	SourceRepositoryURI             = "source-repository-uri"
	SourceRepositoryIdentifier      = "source-repository-identifier"
	SourceRepositoryOwnerURI        = "source-repository-owner-uri"
	SourceRepositoryOwnerIdentifier = "source-repository-owner-identifier"
	BuildConfigURI                  = "build-config-uri"
)

// Claim pairs a claim name with the OID of the Fulcio X.509 extension that
// carries the same claim.
type Claim struct {
	Name      string
	FulcioOID asn1.ObjectIdentifier
}

// Allowlisted lists the claims that both MapFns index.
var Allowlisted = []Claim{
	{BuildSignerURI, asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 9}},
	{SourceRepositoryURI, asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 12}},
	{SourceRepositoryIdentifier, asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 15}},
	{SourceRepositoryOwnerURI, asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 16}},
	{SourceRepositoryOwnerIdentifier, asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 17}},
	{BuildConfigURI, asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 18}},
}

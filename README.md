# vindex-sigstore

`vindex-sigstore` packages the [Verifiable Index (`vindexd`)](https://github.com/transparency-dev/incubator/tree/main/vindex) daemon and Sigstore's Rekor Identity Monitor WebAssembly mapping functions (`mapper-hashedrekord.wasm` and `mapper-identity.wasm`) as independent, separately verifiable artifacts.

## Architecture & Published Artifacts

This repository builds and publishes separate artifacts for `vindexd` and each Rekor shard `MapFn` so that `vindexd` can be upgraded independently of the immutable `.wasm` modules, and external auditors can download and verify each `.wasm` binary directly:

1. **Rekor v2 `hashedrekord v0.0.2` MapFn (`mapper-hashedrekord.wasm` & `ghcr.io/sigstore/vindex-sigstore/mapfn-hashedrekord`)**
   * Reproducibly compiles `./mapfn/hashedrekord` + `./pkg/mapper/hashedrekord` (`GOOS=wasip1 GOARCH=wasm CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags="-buildid=" -buildmode=c-shared`).
   * Published as a raw `mapper-hashedrekord.wasm` (+ `.sha256`) release/workflow artifact with a SLSA build provenance attestation (`gh attestation verify mapper-hashedrekord.wasm --repo sigstore/vindex-sigstore`), and packaged at `/mapper.wasm` inside `ghcr.io/sigstore/vindex-sigstore/mapfn-hashedrekord`.

2. **Rekor PQC `identity v0.0.1` MapFn (`mapper-identity.wasm` & `ghcr.io/sigstore/vindex-sigstore/mapfn-identity`)**
   * Reproducibly compiles `./mapfn/identity` + `./pkg/mapper/identity` for C2SP `identity-transparency` version `0x01` binary leaves.
   * Published as a raw `mapper-identity.wasm` (+ `.sha256`) release/workflow artifact with SLSA provenance (`gh attestation verify mapper-identity.wasm --repo sigstore/vindex-sigstore`), and packaged at `/mapper.wasm` inside `ghcr.io/sigstore/vindex-sigstore/mapfn-identity`.

3. **`ghcr.io/sigstore/vindex-sigstore/vindexd` (`Dockerfile`)**
   * Compiles `vindexd` from `github.com/transparency-dev/incubator/vindex/cmd/vindexd` without baking in a `.wasm` file, consuming `/etc/vindex/mapper.wasm` from the mounted `mapfn-*` volume (via Kubernetes 1.33+ OCI `image` volume or Docker Compose / `initContainer` copy).
   * Runs unprivileged as `nonroot` (`65532:65532`) on `gcr.io/distroless/static-debian13:nonroot` (`deploy` target), with `local-deploy` and `debug` (`dlv`) stages for local development.
   * Pre-creates `/mnt/disks/data`, `/mnt/disks/mpt`, and `/etc/vindex` owned by `65532:65532` across **two separate Persistent SSD mounts** (`pd-ssd` / `pd-balanced` / `hyperdisk-balanced`):
     * **Disk 1 (`/mnt/disks/data`):** PebbleDB (`--db_path=/mnt/disks/data/pebble`), Output Log (`--output_log_dir=/mnt/disks/data/outlog`), and Tile Cache (`--tile_cache_dir=/mnt/disks/data/tiles`).
     * **Disk 2 (`/mnt/disks/mpt`):** Merkle Patricia Trie (`--mpt_dir=/mnt/disks/mpt/tree`, storing `mpt.tree1`, `mpt.tree2`, and `mpt.disk`).

---

## Dual-Persistent-Disk Layout Rationale

In Kubernetes / GKE, `vindexd` is deployed as a `StatefulSet` with two `volumeClaimTemplates` (`data-pvc` mounted at `/mnt/disks/data` and `mpt-pvc` mounted at `/mnt/disks/mpt`), each backed by a persistent SSD volume (`pd-ssd`, `pd-balanced`, or `hyperdisk-balanced`), and `securityContext.fsGroup: 65532` (`fsGroupChangePolicy: OnRootMismatch`) so `vindexd` can create its subdirectories directly on the mounted disks:

1. **Filesystem Journal & `fsync` Isolation (`Disk 1` vs. `Disk 2`):**
   Separating PebbleDB (`Disk 1`) from the MPT (`Disk 2`) places them on distinct Linux block devices (`/dev/nvme0n1` and `/dev/nvme0n2`) with independent kernel block queues, per-volume IOPS/throughput quotas, and independent `ext4` journals (`jbd2`). Sequential MPT patch-frame syncs (`pmem.Sync`) never block or contend with PebbleDB LSM memtable flushes (`pebble.Sync`) or background SSTable compactions.
2. **Instant Warm Recovery Across Node Upgrades (`Phase1` vs. `Phase2`):**
   Because PebbleDB keys leaf-index chunks by `SHA256(key)` (`'c' + 32B KeyHash + ^chunkNum`) and does not store raw variable-length canonical key strings, losing `--mpt_dir` (which would occur on every GKE node upgrade or VM preemption if `--mpt_dir` were placed on an ephemeral `local-ssd`) forces `Coordinator.Phase2` to re-stream and re-map the entire Input Log shard from leaf `0` through `mapper.wasm` to rediscover the canonical keys. Keeping `--mpt_dir` on its own **Persistent SSD** (`Disk 2`) allows both disks to detach and reattach together when a pod is rescheduled, completing `Coordinator.Phase1` startup verification in `< 5ms` after `mpt.Open()`.
3. **Zero Swap Required:**
   Under the Identity-Only index, all 52-byte internal MPT nodes (`t.mem`) fit in anonymous RAM and the append-only leaf file (`mpt.disk`) remains cached in the Linux OS page cache, eliminating any need for a swapfile or privileged `swapon` initialization.

---

## Canonical Key Format & Query Modes

No normalization (such as lowercasing or whitespace trimming) is applied by either `MapFn`; clients query exact values.

The `hashedrekord` `MapFn` percent-encodes every byte of a key outside printable non-whitespace ASCII (`0x21`–`0x7E`) as `%XX` with uppercase hex, so `alice smith@example.com` is indexed as `alice%20smith@example.com:<issuer>` and `é` as `%C3%A9`. A literal `%` is left as is. Clients must encode the keys and prefixes they query the same way (`hashedrekord.PercentEncode`). A key that is empty, or longer than 1024 bytes after encoding, is not indexed.

### 1. `hashedrekord v0.0.2` (`pkg/mapper/hashedrekord`)

| Subject Type | Emitted Canonical Key | Exact Point Lookup (`GET /keys?key=<key>`) | Prefix Lookup (`GET /keys?prefix=<prefix>`) |
| :--- | :--- | :--- | :--- |
| **Email SAN** | `<email>:<issuer>` | `alice@example.com:https://accounts.google.com` | Any issuer: `alice@example.com:` |
| **URI SAN** | `<uri>:<issuer>` | `https://github.com/org/repo/.github/workflows/release.yml@refs/tags/v1.0.0:https://token.actions.githubusercontent.com` | Any issuer: `<full_uri>:`<br>All refs for workflow: `https://github.com/org/repo/.github/workflows/release.yml@`<br>All workflows in repo: `https://github.com/org/repo/` |
| **Fulcio extension** | `<claim_name>:<value>:<issuer>` | `source-repository-uri:https://github.com/org/repo:https://token.actions.githubusercontent.com` | Any issuer: `source-repository-uri:https://github.com/org/repo:`<br>All repos in org: `source-repository-uri:https://github.com/org/` |
| **Public Key** | `hex(SHA256(spki_der))` | `<64-char hex>` | Short hex prefix |

Fulcio extensions are keyed by claim name, not by OID. The indexed claims and their OIDs are defined once in `pkg/mapper/claim` and shared with the `identity v0.0.1` MapFn. The indexed extensions are `build-signer-uri` (`1.3.6.1.4.1.57264.1.9`), `source-repository-uri` (`.1.12`), `source-repository-identifier` (`.1.15`), `source-repository-owner-uri` (`.1.16`), `source-repository-owner-identifier` (`.1.17`), and `build-config-uri` (`.1.18`).

### 2. `identity v0.0.1` (`pkg/mapper/identity`)

| Subject Type | Emitted Canonical Key | Client Lookup Construction (`H2(x) = hex(SHA256(SHA256(x)))`) | Any-Issuer Prefix Lookup (`GET /keys?prefix=<prefix>`) |
| :--- | :--- | :--- | :--- |
| **OIDC Identity** | `hex(VH[identity]):hex(VH[issuer])` | `H2(<identity>):H2(<issuer>)` | `H2(<identity>):` |
| **OIDC Claim** *(6 allowlisted)* | `hex(KH[claim]):hex(VH[claim]):hex(VH[issuer])` | `H2(<claim_name>):H2(<value>):H2(<issuer>)` | `H2(<claim_name>):H2(<value>):` |
| **Public Key** | `hex(root_of_trust)` | `hex(SHA256("<algorithm>" \|\| spki_der))` | N/A |

Allowlisted `identity v0.0.1` claim names: `build-signer-uri`, `source-repository-uri`, `source-repository-identifier`, `source-repository-owner-uri`, `source-repository-owner-identifier`, `build-config-uri`.

---

## Web UI (`webui/`)

[`webui/`](webui/) contains the static Sigstore-branded Rekor Identity Monitor single-page application (`index.html`, `index.css`, `app.js`, and `config.json`), designed to be served directly from a static bucket (such as Google Cloud Storage + Cloud CDN) or an unprivileged Nginx container.

On page load, `app.js` fetches a relative [`config.json`](webui/config.json) file so the same static HTML/CSS/JS assets can be deployed in front of either a `hashedrekord v0.0.2` or an `identity v0.0.1` shard without modifying the bundle:

```json
{
  "shardType": "hashedrekord",
  "shardFormat": "hashedrekord v0.0.2",
  "shardLabel": "log2025-1.rekor.sigstore.dev · hashedrekord v0.0.2",
  "vindexBaseURL": "",
  "inputLogURL": "https://log2025-1.rekor.sigstore.dev/api/v2",
  "inputLogPublicKey": "log2025-1.rekor.sigstore.dev+cf119915+AbfK5adZJxsI323FwGD2AJJ9F4i89cfDuLdGJBIYntuO"
}
```

* **`shardType`:** `"hashedrekord"` (default) or `"identity"` (enables double-SHA-256 OIDC key construction, algorithm-prefixed SPKI public key hashing, and binary `0x01` leaf decoding).
* **`shardFormat` / `shardLabel`:** Display strings shown in the UI's shard badge and proof inspector.
* **`vindexBaseURL`:** Base URL of the `vindexd` read API (empty `""` when served from the same origin/load balancer path as `/keys` and `/values`, or a full origin such as `"https://vindex.rekor.sigstore.dev"` when hosted on a separate static domain).
* **`inputLogURL`:** Base `tlog-tiles` URL of the upstream Rekor shard used when inspecting raw log leaves (`/tile/entries/...`) and when checking the Rekor log state (`/checkpoint` and `/tile/<level>/...`).
* **`inputLogPublicKey`:** Rekor's checkpoint verifier key in note format (`<name>+<key hash>+<base64 key>`), the same value as `vindexd --input_log_pubkey`. Optional.

On every search the page checks the Rekor log size and root hash in the `/keys` response against Rekor itself. It fetches Rekor's checkpoint, verifies the checkpoint signature against `inputLogPublicKey`, and uses Rekor's hash tiles to check that the size and root hash are a prefix of the log the checkpoint commits to. A mismatch is reported as an error and the results are withheld. If the check cannot be completed, the results are shown with a warning. The page verifies Ed25519 and ML-DSA-44 checkpoint signatures with the browser's built-in Web Crypto API. With no key configured, with another key type, or in a browser whose Web Crypto API lacks the algorithm (ML-DSA-44 is not yet available in every browser), it still runs the consistency check but reports that the signature was not verified.

In Kubernetes/Nginx deployments, mount a `ConfigMap` over `/usr/share/nginx/html/config.json` (or render it at container startup via Nginx's `/etc/nginx/templates/` `envsubst`). In GCS deployments, upload a shard-specific `config.json` alongside `index.html` in each bucket or path prefix.

Queries and inspected log entries automatically sync to URL `#...` hash fragments (for example `#tab=cert&subject=alice@example.com&entry=235`), providing shareable stateless deep links without transmitting cleartext query parameters to static-host or CDN access logs.

---

## Building Locally

```bash
# Build bin/mapper-hashedrekord.wasm, bin/mapper-identity.wasm, and bin/vindexd
make all

# Build only the WebAssembly MapFns (wasip1/wasm)
make wasm

# Generate an Ed25519 Note signing and verification keypair for the Output Log
make keygen
# Or specify a custom origin:
make keygen ORIGIN=my.vindex.org

# Build Docker images (vindexd, mapfn-hashedrekord, and mapfn-identity)
make docker-build
```

## Local Deployment with Docker Compose

Run `docker compose up --build` (setting `OUTPUT_LOG_SIGNER_KEY`, and optionally `MAPFN_TYPE=identity` for Rekor PQC shards) to populate `vindex_wasm` and start `vindexd`:

```bash
OUTPUT_LOG_SIGNER_KEY="PRIVATE+KEY+..." docker compose up --build

# Or for an identity v0.0.1 (Rekor PQC) shard:
MAPFN_TYPE=identity \
INPUT_LOG_URL="https://pqc27-a1.us-east4.rekor.sigstage.dev/api/v2" \
INPUT_LOG_ORIGIN="..." \
INPUT_LOG_PUBKEY="..." \
OUTPUT_LOG_SIGNER_KEY="PRIVATE+KEY+..." \
docker compose up --build
```

To bind-mount two specific host disks instead of Docker-managed named volumes, ensure the host mountpoints are owned by `65532:65532` and pass `DATA_DISK_PATH` and `MPT_DISK_PATH`:

```bash
sudo chown 65532:65532 /mnt/disks/ssd0 /mnt/disks/ssd1
DATA_DISK_PATH=/mnt/disks/ssd0 \
MPT_DISK_PATH=/mnt/disks/ssd1 \
OUTPUT_LOG_SIGNER_KEY="PRIVATE+KEY+..." \
docker compose up --build
```

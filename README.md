# vindex-sigstore

`vindex-sigstore` packages the [Verifiable Index (`vindexd`)](https://github.com/transparency-dev/incubator/tree/main/vindex/v1) daemon with Sigstore's Rekor v2 Identity Monitor WebAssembly mapping function (`mapper.wasm`) and disk/swap initialization tooling.

## Architecture & Container Images

This repository produces two container images modeled on [`sigstore/rekor-tiles`](https://github.com/sigstore/rekor-tiles):

1. **`ghcr.io/sigstore/vindex-sigstore/vindex-init` (`Dockerfile.init`)**
   * Runs as a privileged `initContainer` prior to `vindexd` startup.
   * Initializes the directory structure and sets `nonroot` (`65532:65532`) ownership across the **two separate disk mounts**:
     * **Disk 1 (`DATA_MOUNT_DIR`, default `/mnt/disks/data`):** Persistent storage for PebbleDB (`/mnt/disks/data/pebble`), the Output Log (`/mnt/disks/data/outlog`), and the Tile Cache (`/mnt/disks/data/tiles`).
     * **Disk 2 (`MPT_MOUNT_DIR`, default `/mnt/disks/mpt`):** Dedicated fast NVMe storage for the memory-mapped Merkle Patricia Trie (`/mnt/disks/mpt/tree`) and optional swapfile (`/mnt/disks/mpt/swapfile`).
   * If `SWAP_SIZE` (e.g., `SWAP_SIZE=32G`) is set, allocates `/mnt/disks/mpt/swapfile`, formats it with `mkswap`, and activates it in the host Linux kernel via `swapon`.

2. **`ghcr.io/sigstore/vindex-sigstore/vindexd` (`Dockerfile`)**
   * Multi-stage build compiling `vindexd` from `github.com/transparency-dev/incubator/vindex/v1/cmd/vindexd` alongside the Sigstore Rekor v2 WebAssembly `MapFn` (`./mapfn` + `./pkg/mapper` $\rightarrow$ `/etc/vindex/mapper.wasm`).
   * Runs unprivileged as `nonroot` (`65532:65532`) on `gcr.io/distroless/static-debian13:nonroot` (`deploy` target), with `local-deploy` and `debug` (`dlv`) stages for local development.

---

## How Init-Container Swap Works with the Main Container

When `vindex-init` runs `swapon /mnt/disks/mpt/swapfile`, the `sys_swapon` system call registers that swap area directly with the **host Linux kernel's Virtual Memory Manager (VMM)** (`mm/swapfile.c`), not a container-private namespace. Once enabled, the kernel pins the swapfile and exposes that swap space node-wide (visible in `/proc/swaps`) even after `vindex-init` exits.

For the unprivileged `vindexd` container to actually page out its memory-mapped MPT or anonymous memory to that kernel swap area, its **cgroup** must be permitted to use swap:
* **Docker / Docker Compose:** Enabled automatically unless `--memory-swap` is explicitly locked equal to `--memory`.
* **Kubernetes / GKE:**
  1. The node's Kubelet must have `NodeSwap` enabled (`failSwapOn: false`, `memorySwap.swapBehavior: LimitedSwap` or `UnlimitedSwap`).
  2. Under `LimitedSwap`, Kubernetes only grants swap (`memory.swap.max > 0`) to Pods in the **Burstable QoS** class—meaning the `vindexd` container should specify `resources.requests.memory` **without** setting an equal `resources.limits.memory`.

---

## Canonical Key Format & Query Modes

`mapper.wasm` ([`pkg/mapper`](pkg/mapper/mapper.go)) emits printable ASCII canonical keys (`0x21..0x7E`) into the VIndex Merkle Patricia Trie (MPT):

| Subject Type | Emitted Canonical Key | Exact Point Lookup (`/vindex/v1/keys/{key}`) | Prefix Lookup (`/vindex/v1/keys/{prefix}?prefix=true`) |
| :--- | :--- | :--- | :--- |
| **Email SAN** | `<email>:<issuer>` | `alice@example.com:https://accounts.google.com` | Any issuer: `alice@example.com:` |
| **URI SAN** | `<uri>:<issuer>` | `https://github.com/org/repo/.github/workflows/release.yml@refs/tags/v1.0.0:https://token.actions.githubusercontent.com` | Any issuer: `<full_uri>:`<br>All refs for workflow: `https://github.com/org/repo/.github/workflows/release.yml@`<br>All workflows in repo: `https://github.com/org/repo/` |
| **Fulcio OID** | `<oid>:<value>:<issuer>` | `1.3.6.1.4.1.57264.1.12:https://github.com/org/repo:https://token.actions.githubusercontent.com` | Any issuer: `1.3.6.1.4.1.57264.1.12:https://github.com/org/repo:`<br>All repos in org: `1.3.6.1.4.1.57264.1.12:https://github.com/org/` |
| **Public Key** | `<64-char hex sha256(spki_der)>` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | Short hex prefix: `e3b0c44298fc` |

---

## Building Locally

Use the `Makefile` to build the WebAssembly `MapFn`, `vindexd` binary, or container images:

```bash
# Build both bin/mapper.wasm and bin/vindexd
make all

# Build only the WebAssembly MapFn (wasip1/wasm)
make wasm

# Generate an Ed25519 Note signing and verification keypair for the Output Log
make keygen
# Or specify a custom origin:
make keygen ORIGIN=my.vindex.org

# Build both Docker images (vindexd and vindex-init)
make docker-build
```

## Local Deployment with Docker Compose

Run `docker compose up --build` (setting `OUTPUT_LOG_SIGNER_KEY` and optional `SWAP_SIZE`) to start the init container followed by `vindexd` with two separate volumes (`vindex_data` and `vindex_mpt`):

```bash
OUTPUT_LOG_SIGNER_KEY="PRIVATE+KEY+..." SWAP_SIZE="4G" docker compose up --build
```

#!/usr/bin/env bash
#
# Copyright 2026 The Sigstore Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

PS4='+\D{%Y-%m-%d %H:%M:%S} $LINENO: '

set -euxo pipefail

# Disk 1: Persistent Disk / storage mount for PebbleDB, Output Log, and Tile Cache
DATA_MOUNT_DIR="${DATA_MOUNT_DIR:-/mnt/disks/data}"

# Disk 2: Dedicated NVMe mount for the memory-mapped MPT and swapfile
MPT_MOUNT_DIR="${MPT_MOUNT_DIR:-/mnt/disks/mpt}"

# UID/GID of the nonroot user in gcr.io/distroless/static-debian13:nonroot
VINDEX_UID="${VINDEX_UID:-65532}"
VINDEX_GID="${VINDEX_GID:-65532}"

# Optional swap configuration on the MPT NVMe disk (e.g. SWAP_SIZE="32G")
SWAP_SIZE="${SWAP_SIZE:-}"
SWAP_FILE="${SWAP_FILE:-${MPT_MOUNT_DIR}/swapfile}"

# 1. Initialize directories on Disk 1 (Data Disk: PebbleDB, Output Log, Tile Cache)
mkdir -p "${DATA_MOUNT_DIR}/pebble" \
         "${DATA_MOUNT_DIR}/outlog" \
         "${DATA_MOUNT_DIR}/tiles"
chown -R "${VINDEX_UID}:${VINDEX_GID}" \
         "${DATA_MOUNT_DIR}/pebble" \
         "${DATA_MOUNT_DIR}/outlog" \
         "${DATA_MOUNT_DIR}/tiles"

# 2. Initialize directories on Disk 2 (MPT NVMe Disk: Memory-Mapped Trie)
mkdir -p "${MPT_MOUNT_DIR}/tree"
chown -R "${VINDEX_UID}:${VINDEX_GID}" "${MPT_MOUNT_DIR}/tree"

# 3. Configure and enable swapfile on Disk 2 if SWAP_SIZE is specified
if [[ -n "${SWAP_SIZE}" && "${SWAP_SIZE}" != "0" ]]; then
    if grep -q "^${SWAP_FILE} " /proc/swaps; then
        echo "Swapfile ${SWAP_FILE} is already active in host kernel."
    else
        echo "Allocating ${SWAP_SIZE} swapfile at ${SWAP_FILE}..."
        rm -f "${SWAP_FILE}"
        if ! fallocate -l "${SWAP_SIZE}" "${SWAP_FILE}"; then
            echo "fallocate not supported on filesystem; falling back to dd..."
            SWAP_MB=$(numfmt --from=iec "${SWAP_SIZE}" | awk '{printf "%d", $1 / (1024 * 1024)}')
            dd if=/dev/zero of="${SWAP_FILE}" bs=1M count="${SWAP_MB}" status=progress
        fi
        chown 0:0 "${SWAP_FILE}"
        chmod 0600 "${SWAP_FILE}"
        mkswap "${SWAP_FILE}"
        swapon "${SWAP_FILE}"
        echo "Swap enabled successfully:"
        swapon --show
    fi
fi

echo "done" > /root/finished

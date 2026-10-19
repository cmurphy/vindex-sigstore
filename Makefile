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

.PHONY: all wasm vindexd keygen docker-build docker-build-vindexd docker-build-init test clean ldflags help

all: wasm vindexd

ORIGIN ?= vindex.rekor.sigstore.dev

GIT_VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
GIT_HASH ?= $(shell git rev-parse HEAD 2>/dev/null || echo "unknown")
DATE_FMT = +%Y-%m-%dT%H:%M:%SZ
SOURCE_DATE_EPOCH ?= $(shell git log -1 --pretty=%ct 2>/dev/null)
ifdef SOURCE_DATE_EPOCH
    BUILD_DATE ?= $(shell date -u -d "@$(SOURCE_DATE_EPOCH)" "$(DATE_FMT)" 2>/dev/null || date -u -r "$(SOURCE_DATE_EPOCH)" "$(DATE_FMT)" 2>/dev/null || date -u "$(DATE_FMT)")
else
    BUILD_DATE ?= $(shell date -u "$(DATE_FMT)")
endif
GIT_TREESTATE = "clean"
DIFF = $(shell git diff --quiet >/dev/null 2>&1; if [ $$? -eq 1 ]; then echo "1"; fi)
ifeq ($(DIFF), 1)
    GIT_TREESTATE = "dirty"
endif

VINDEX_LDFLAGS=-buildid= \
               -X sigs.k8s.io/release-utils/version.gitVersion=$(GIT_VERSION) \
               -X sigs.k8s.io/release-utils/version.gitCommit=$(GIT_HASH) \
               -X sigs.k8s.io/release-utils/version.gitTreeState=$(GIT_TREESTATE) \
               -X sigs.k8s.io/release-utils/version.buildDate=$(BUILD_DATE)
SERVER_LDFLAGS=$(VINDEX_LDFLAGS)

IMAGE_REPO ?= ghcr.io/sigstore/vindex-sigstore
DOCKER_TARGET ?= deploy

wasm: ## Compile the Rekor v2 identity MapFn to WebAssembly (wasip1/wasm)
	@mkdir -p bin
	GOOS=wasip1 GOARCH=wasm CGO_ENABLED=0 go build -trimpath -ldflags="-buildid=" -buildmode=c-shared -o bin/mapper.wasm ./mapfn

vindexd: ## Build the vindexd server binary from upstream module
	@mkdir -p bin
	CGO_ENABLED=0 go build -trimpath -ldflags "$(SERVER_LDFLAGS)" -o bin/vindexd github.com/transparency-dev/incubator/vindex/v1/cmd/vindexd

keygen: ## Generate an Ed25519 Note signing and verification keypair (override origin with ORIGIN=...)
	@go run github.com/transparency-dev/incubator/scripts/keygen "$(ORIGIN)"

docker-build: docker-build-vindexd docker-build-init ## Build both vindexd and vindex-init container images

docker-build-vindexd: ## Build the vindexd container image (includes compiled mapper.wasm)
	docker build --target $(DOCKER_TARGET) \
		--build-arg SERVER_LDFLAGS="$(SERVER_LDFLAGS)" \
		-t $(IMAGE_REPO)/vindexd:$(GIT_VERSION) \
		-t $(IMAGE_REPO)/vindexd:latest \
		-f Dockerfile .

docker-build-init: ## Build the vindex-init container image (disk and swap initialization)
	docker build \
		-t $(IMAGE_REPO)/vindex-init:$(GIT_VERSION) \
		-t $(IMAGE_REPO)/vindex-init:latest \
		-f Dockerfile.init .

ldflags: ## Print ldflags
	@echo $(SERVER_LDFLAGS)

test: ## Run all unit tests
	go test ./...

clean: ## Remove built binaries and artifacts
	rm -rf bin dist vindexd vindexd_debug *.wasm

##################
# help
##################

help: ## Display this help message
	@echo "Usage: make <target>"
	@echo ""
	@echo "Targets:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z0-9_-]+:.*?## / {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

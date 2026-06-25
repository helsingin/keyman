CONTAINER_RUNTIME ?= $(shell if command -v docker >/dev/null 2>&1; then echo docker; else echo podman; fi)
ifeq ($(CONTAINER_RUNTIME),podman)
CONTAINER_BUILD_FLAGS ?= --pull=missing
else
CONTAINER_BUILD_FLAGS ?=
endif
HOST ?= 127.0.0.1
PORT ?= 8080
CONTAINER_NAME ?= keyman-demo

.PHONY: test test-integration tidy web-install web-build server-build build container-build container-run demo docker-build

test:
	go test ./...

test-integration:
	./scripts/run-softhsm-tests.sh

tidy:
	go mod tidy

web-install:
	cd web && pnpm install

web-build:
	cd web && pnpm build

server-build:
	go build -o bin/keymand ./cmd/keymand

build: web-build server-build

container-build:
	$(CONTAINER_RUNTIME) build $(CONTAINER_BUILD_FLAGS) -f build/Dockerfile -t keyman:latest .

container-run:
	$(CONTAINER_RUNTIME) run --rm --name $(CONTAINER_NAME) -p $(HOST):$(PORT):8080 keyman:latest

demo: container-build container-run

docker-build: container-build

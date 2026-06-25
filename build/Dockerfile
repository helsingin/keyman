# syntax=docker/dockerfile:1.7

FROM node:24-bookworm AS web

ENV COREPACK_HOME=/root/.cache/node/corepack

RUN corepack enable

WORKDIR /src/web
COPY web/package.json web/pnpm-lock.yaml ./
RUN --mount=type=cache,target=/root/.cache/node/corepack \
    --mount=type=cache,target=/root/.local/share/pnpm/store \
    pnpm install --frozen-lockfile --store-dir /root/.local/share/pnpm/store
COPY web/ ./
RUN --mount=type=cache,target=/root/.cache/node/corepack \
    pnpm build

FROM golang:1.24-bookworm AS go-build

WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download
COPY . .
COPY --from=web /src/web/dist ./web/dist
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=1 go build -o /out/keymand ./cmd/keymand

FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    opensc \
    softhsm2 \
    swtpm \
    tpm2-tools

RUN mkdir -p /var/lib/softhsm/tokens \
    && softhsm2-util --init-token --free --label "KEYMAN" --so-pin 1234 --pin 1234

ENV KEYMAN_ADDR=:8080
ENV KEYMAN_STATIC_DIR=/app/web
ENV KEYMAN_TPM2_DEMO=1
ENV KEYMAN_TPM2_STATE_DIR=/var/lib/keyman/swtpm
ENV PKCS11_MODULE_PATH=/usr/lib/softhsm/libsofthsm2.so
ENV PKCS11_TOKEN_LABEL=KEYMAN
ENV TPM2TOOLS_TCTI=swtpm:host=127.0.0.1,port=2321

WORKDIR /app
COPY --from=go-build /out/keymand /app/keymand
COPY --from=web /src/web/dist /app/web
COPY build/entrypoint.sh /app/entrypoint.sh

EXPOSE 8080

CMD ["/app/entrypoint.sh"]

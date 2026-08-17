# ---- Rust stage: the cozk2p PLONK-verifier staticlib ----
# The build context is the REPO ROOT (see docker-compose.yml): the chain
# links cozk2p as a cgo staticlib, so the image build needs both trees.
FROM rust:1.85 AS rustbuilder

WORKDIR /src
COPY cozk2p/ cozk2p/
# rustup resolves the pinned nightly from cozk2p/rust-toolchain.toml.
RUN cd cozk2p && cargo build --release --lib

# ---- Go stage: chain binary WITH the cozk2p verifier ----
FROM golang:1.25.7 AS builder

WORKDIR /build
COPY chain/go.mod chain/go.sum ./
RUN go mod download
COPY chain/ .
COPY --from=rustbuilder /src/cozk2p/target/release/libcozk2p.a lib/
RUN CGO_ENABLED=1 GOOS=linux go build -tags cozk2p -o invisibook .

# ---- Runtime stage ----
FROM ubuntu:24.04

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /build/invisibook .
COPY chain/cfg/ cfg/
COPY chain/vk/ vk/

EXPOSE 7999 8999 8887

ENTRYPOINT ["./invisibook"]

# ── Stage 1: Build web frontend ──
FROM node:24-alpine AS frontend
WORKDIR /app/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ .
# The prebuild hook checks node_modules against the lockfile with this shared script
COPY scripts/check-deps.mjs /app/scripts/
RUN npm run build

# ── Stage 2: Build Rust server (embeds web/dist via rust-embed) ──
# sqlx 0.9 requires Rust 1.94+; aws-lc-sys (rustls crypto provider) needs a C toolchain.
FROM rust:1.99-alpine AS builder
RUN apk add --no-cache musl-dev cmake make perl pkgconfig
WORKDIR /app

# 1) Copy manifests only and create stub source files to cache dependency compilation
COPY Cargo.toml Cargo.lock ./
COPY crates/cpmesh-proto/Cargo.toml crates/cpmesh-proto/Cargo.toml
COPY crates/cpmesh-server/Cargo.toml crates/cpmesh-server/Cargo.toml
RUN mkdir -p crates/cpmesh-proto/src && echo "// stub" > crates/cpmesh-proto/src/lib.rs \
 && mkdir -p crates/cpmesh-server/src && echo "// stub" > crates/cpmesh-server/src/lib.rs \
 && echo "fn main() {}" > crates/cpmesh-server/src/main.rs \
 && mkdir -p web/dist && echo "" > web/dist/index.html
RUN cargo build --release -p cpmesh-server 2>/dev/null || true
# Remove stub fingerprints so the real source triggers a recompile
RUN rm -rf target/release/.fingerprint/cpmesh-proto-* \
           target/release/.fingerprint/cpmesh-server-*

# 2) Copy real source and frontend build, then compile
COPY crates/ crates/
COPY --from=frontend /app/web/dist/ web/dist/
RUN cargo build --release -p cpmesh-server

# ── Stage 3: Final minimal image ──
FROM alpine:3.24
RUN apk add --no-cache ca-certificates && mkdir -p /srv/downloads

COPY --from=builder /app/target/release/cpmesh-server /usr/local/bin/cpmesh-server

# Pre-built installers from the optional local downloads/ directory. The wildcard
# tolerates a missing directory; LICENSE-MIT only guarantees COPY has a source.
COPY LICENSE-MIT downloads*/ /srv/downloads/
RUN rm -f /srv/downloads/LICENSE-MIT

ENV DOWNLOADS_DIR=/srv/downloads
EXPOSE 8080
CMD ["cpmesh-server"]

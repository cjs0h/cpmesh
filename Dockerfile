# ── Stage 1: Build web frontend ──
FROM node:22-alpine AS frontend
WORKDIR /app/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ .
RUN npm run build

# ── Stage 2: Build Rust server (embeds web/dist via rust-embed) ──
FROM rust:1.88-alpine AS builder
RUN apk add --no-cache musl-dev openssl-dev openssl-libs-static pkgconfig
WORKDIR /app

# 1) Copy manifests only and create stub source files to cache dependency compilation
COPY Cargo.toml Cargo.lock ./
COPY crates/cpmesh-proto/Cargo.toml crates/cpmesh-proto/Cargo.toml
COPY crates/cpmesh-server/Cargo.toml crates/cpmesh-server/Cargo.toml
RUN mkdir -p crates/cpmesh-proto/src && echo "// stub" > crates/cpmesh-proto/src/lib.rs \
 && mkdir -p crates/cpmesh-server/src && echo "fn main() {}" > crates/cpmesh-server/src/main.rs \
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
FROM alpine:3.21
RUN apk add --no-cache ca-certificates

COPY --from=builder /app/target/release/cpmesh-server /usr/local/bin/cpmesh-server

# Copy pre-built installers from local downloads/ directory
COPY downloads/ /srv/downloads/

ENV DOWNLOADS_DIR=/srv/downloads
EXPOSE 8080
CMD ["cpmesh-server"]

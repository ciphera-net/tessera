# Build stage — use a current stable Rust (edition 2024 needs >= 1.85)
FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --bin tessera-sidecar

# Runtime stage — distroless, no shell
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /src/target/release/tessera-sidecar /usr/local/bin/tessera-sidecar
ENTRYPOINT ["/usr/local/bin/tessera-sidecar"]
# NOTE: this CMD is the local-`docker run` default; the Nomad stanza overrides it with the
# alloc-dir socket path (/alloc/tessera/tessera.sock).
CMD ["serve", "/run/tessera/tessera.sock", "/secrets/server-setup.bin"]

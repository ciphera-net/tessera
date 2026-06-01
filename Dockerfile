# Build stage — use a current stable Rust (edition 2024 needs >= 1.85)
FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --bin tessera-sidecar

# Runtime stage — distroless, no shell
FROM gcr.io/distroless/cc-debian12
COPY --from=build /src/target/release/tessera-sidecar /usr/local/bin/tessera-sidecar
ENTRYPOINT ["/usr/local/bin/tessera-sidecar"]
CMD ["serve", "/run/tessera/tessera.sock", "/secrets/server-setup.bin"]

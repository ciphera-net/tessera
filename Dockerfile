# Build stage — rust:1-bookworm (edition 2024 needs >= 1.85). Pinned by digest for reproducibility.
FROM rust:1-bookworm@sha256:13c186980fa33cc12759b429662a1322939dbe697484b7c33b47dd2698d28460 AS build
WORKDIR /src
COPY . .
RUN cargo build --release --bin tessera-sidecar

# Runtime stage — distroless nonroot (gcr.io/distroless/cc-debian12:nonroot). Pinned by digest.
FROM gcr.io/distroless/cc-debian12:nonroot@sha256:bd2899c12b335c827750ccf2359879eab09c09b206023dcebea408947d54127c
COPY --from=build /src/target/release/tessera-sidecar /usr/local/bin/tessera-sidecar
ENTRYPOINT ["/usr/local/bin/tessera-sidecar"]
# NOTE: this CMD is the local-`docker run` default; the Nomad stanza overrides args with the
# alloc-dir socket path (/alloc/tessera/tessera.sock).
CMD ["serve", "/run/tessera/tessera.sock", "/secrets/server-setup.bin"]

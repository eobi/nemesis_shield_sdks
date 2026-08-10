# Rust SDK: tokenizer parity (36 vectors, via cargo test) + live sketch round-trip, on rust:1-slim.
# build-essential/perl are needed to compile ureq's TLS stack (ring) from source.
FROM rust:1-slim
RUN apt-get update && apt-get install -y --no-install-recommends build-essential perl pkg-config \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /work
COPY tokenize.vectors.json /work/tokenize.vectors.json
COPY rust/ /work/rust/
# The parity test uses include_str!("../../tokenize.vectors.json"); the round-trip is a crate example.
COPY e2e/rust/roundtrip.rs /work/rust/examples/roundtrip.rs
WORKDIR /work/rust
# Warm the build (compile deps once) so the run phase is fast and offline-safe.
RUN cargo build --tests --examples
CMD sh -c '\
  echo "== PARITY (rust) ==" && \
  cargo test --test parity -- --nocapture && echo "PARITY_OK 36/36" && \
  echo "== ROUNDTRIP (rust) ==" && \
  cargo run --example roundtrip'

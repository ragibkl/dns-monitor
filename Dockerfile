## builder
# Keep the Rust version in step with .tool-versions (CI checks they match).
FROM rust:1.100.0-alpine3.24 AS builder

WORKDIR /code/dns-monitor

# Link musl dynamically, as Alpine's own rust package does. The official image
# defaults to static binaries, and a static build script cannot dlopen
# libclang. The runtime stage already installs libgcc and libstdc++.
ENV RUSTFLAGS="-C target-feature=-crt-static"

# install system dependencies. aws-lc-rs, which rustls uses for its crypto,
# builds C and needs clang to generate its bindings.
RUN apk add --no-cache \
    build-base \
    clang \
    clang-dev \
    clang-libs \
    cmake \
    linux-headers

# setup build dependencies
RUN cargo init .
COPY Cargo.toml Cargo.lock ./
RUN cargo build --release
RUN rm -rf ./src/

# copy code files
COPY /src/ ./src/

# build code
RUN touch ./src/main.rs
RUN cargo build --release


## runtime
FROM alpine:3.24 AS runtime

# ca-certificates provides the trust store that both the DoH check and the DoT
# and certificate checks verify against. Without it every check fails closed.
RUN apk add --no-cache ca-certificates libgcc libstdc++

# set default logging, can be overridden
ENV RUST_LOG=info

# copy binary
COPY --from=builder /code/dns-monitor/target/release/dns-monitor /usr/local/bin/dns-monitor

# health server, used as the Deployment's liveness probe
EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/dns-monitor"]

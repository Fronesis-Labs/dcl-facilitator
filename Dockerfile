# syntax=docker/dockerfile:1

# ---- build: native Debian GNU target ----------------------------------------
FROM rust:1-bookworm AS build
RUN apt-get update \
    && apt-get install -y --no-install-recommends pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

# ---- runtime: non-root Debian with OpenSSL ----------------------------------
FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 65532 --user-group facilitator
COPY --from=build /src/target/release/dcl-facilitator /dcl-facilitator
# Inside the container the service must listen on all interfaces so that the
# published port works. Restrict exposure on the host side instead, e.g.
#   docker run -p 127.0.0.1:8080:8080 ...
ENV HOST=0.0.0.0 PORT=8080
EXPOSE 8080
USER facilitator
ENTRYPOINT ["/dcl-facilitator"]

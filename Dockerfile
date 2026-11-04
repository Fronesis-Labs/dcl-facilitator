# syntax=docker/dockerfile:1

# ---- build: static musl binary ----------------------------------------------
FROM rust:1-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
ENV RUSTFLAGS="-C target-feature=+crt-static"
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

# ---- runtime: no shell, no package manager, non-root --------------------------
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /src/target/release/dcl-facilitator /dcl-facilitator
# Inside the container the service must listen on all interfaces so that the
# published port works. Restrict exposure on the host side instead, e.g.
#   docker run -p 127.0.0.1:8080:8080 ...
ENV HOST=0.0.0.0 PORT=8080
EXPOSE 8080
ENTRYPOINT ["/dcl-facilitator"]

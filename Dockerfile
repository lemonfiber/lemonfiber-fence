# The fence's image: the program that installs the rules, and nftables to install them.
#
# The build stage compiles a static binary for the platform being built. The image
# holds that binary, nftables and tini, and runs tini as its first process, so the
# fence holding the namespace ends on the engine's stop signal rather than waiting out
# the stop timeout. It runs as root because installing rules needs `NET_ADMIN`, which
# lemonfiber grants this container alone; the service behind it shares the namespace
# and holds no capability. Its health check asks the kernel whether the rules are in
# force.

FROM rust:1.99.1-alpine3.22@sha256:731f64e16c12af70970d9a3655eecb1eecab4898352f09688a8e5ca2ab8b77c5 AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked && cp target/release/fence /fence

FROM alpine:3.24@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a
RUN apk add --no-cache nftables tini
COPY --from=build /fence /usr/local/bin/fence
HEALTHCHECK --interval=10s --timeout=5s --start-period=5s --retries=3 CMD ["/usr/local/bin/fence", "health"]
ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/fence"]

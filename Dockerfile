ARG RUST_VERSION=1.77
ARG DEBIAN_VERSION=bookworm
FROM --platform=${BUILDPLATFORM:-linux/amd64} rust:${RUST_VERSION}-slim-${DEBIAN_VERSION} as builder
ARG BUILD_DEPS="binutils libssl-dev pkg-config git"
WORKDIR /usr/src/operator
COPY . .
RUN CARGO_NET_GIT_FETCH_WITH_CLI=true cargo build --features=telemetry --release --bin controller \
 && strip target/release/controller

FROM --platform=${BUILDPLATFORM:-linux/amd64} debian:${DEBIAN_VERSION}-slim as target
ARG DEB_PACKAGES="openssl"
# hadolint ignore=DL3027,DL3008
RUN DEBIAN_FRONTEND=noninteractive apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get -y upgrade \
 && DEBIAN_FRONTEND=noninteractive apt-get -y install --no-install-recommends ${DEB_PACKAGES} \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /work \
 && chown nobody:nogroup /work
COPY --from=builder /usr/src/operator/target/release/controller /usr/local/bin/controller
USER nobody
WORKDIR /work
ENTRYPOINT ["controller"]

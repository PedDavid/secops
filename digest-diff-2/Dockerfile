# syntax=docker/dockerfile:1
FROM rust:1.94.0-bookworm AS build
WORKDIR /src
ARG CARGO_BUILD_JOBS=3
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target,sharing=locked \
    --mount=type=secret,id=proxy_ca \
    if [ -f /run/secrets/proxy_ca ]; then export CARGO_HTTP_CAINFO=/run/secrets/proxy_ca; fi; \
    cargo +1.94.0 clean --release -p digest-diff-2 && \
    cargo +1.94.0 build --release --locked --bin digest-diff-2 && cp target/release/digest-diff-2 /digest-diff-2

FROM golang:1.26.9-bookworm AS scanners
ARG SYFT_VERSION=1.54.1
ARG SYFT_SHA256=c069905b391cc4c20a5ba65ad5c10be2a7ba074f8ea6ad203e24d14e303dad47
ARG GRYPE_VERSION=0.120.1
ARG GRYPE_SHA256=0a9ee97ef5ae2ee953b0a80098105052e846cdbe319a57d808b519c33cd1343d
RUN --mount=type=secret,id=proxy_ca \
    if [ -f /run/secrets/proxy_ca ]; then export CURL_CA_BUNDLE=/run/secrets/proxy_ca; fi; \
    curl -fsSL --retry 3 "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_linux_amd64.tar.gz" -o /tmp/syft.tar.gz && \
    echo "${SYFT_SHA256}  /tmp/syft.tar.gz" | sha256sum -c - && \
    tar -xzf /tmp/syft.tar.gz -C /usr/local/bin syft && \
    curl -fsSL --retry 3 "https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_linux_amd64.tar.gz" -o /tmp/grype.tar.gz && \
    echo "${GRYPE_SHA256}  /tmp/grype.tar.gz" | sha256sum -c - && \
    tar -xzf /tmp/grype.tar.gz -C /usr/local/bin grype && mkdir /data && chown 65532:65532 /data

FROM gcr.io/distroless/cc-debian12:nonroot
LABEL org.opencontainers.image.source="https://github.com/PedDavid/secops"
LABEL org.opencontainers.image.description="Digest comparison on the clavium/dominium/lastmile application foundation"
COPY --from=build /digest-diff-2 /usr/local/bin/digest-diff-2
COPY --from=scanners /usr/local/bin/syft /usr/local/bin/grype /usr/local/bin/
COPY --from=scanners --chown=65532:65532 /data /data
USER 65532:65532
ENV HOME=/tmp
EXPOSE 8080 9090
ENTRYPOINT ["/usr/local/bin/digest-diff-2"]

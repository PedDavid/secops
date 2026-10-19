# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM golang:1.26.9-bookworm AS builder
WORKDIR /app
COPY go.mod ./
RUN go mod download
COPY . .
ARG TARGETARCH
RUN test "$TARGETARCH" = amd64 && \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /digest-diff . && mkdir /cache

FROM --platform=$BUILDPLATFORM golang:1.26.9-bookworm AS tools
ARG SYFT_VERSION=1.54.1
ARG SYFT_SHA256=c069905b391cc4c20a5ba65ad5c10be2a7ba074f8ea6ad203e24d14e303dad47
ARG GRYPE_VERSION=0.120.1
ARG GRYPE_SHA256=0a9ee97ef5ae2ee953b0a80098105052e846cdbe319a57d808b519c33cd1343d
RUN --mount=type=secret,id=build_ca \
    if [ -f /run/secrets/build_ca ]; then export CURL_CA_BUNDLE=/run/secrets/build_ca; fi; \
    curl -fsSL --retry 3 "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_linux_amd64.tar.gz" -o /tmp/syft.tar.gz && \
    echo "${SYFT_SHA256}  /tmp/syft.tar.gz" | sha256sum -c - && \
    tar -xzf /tmp/syft.tar.gz -C /usr/local/bin syft && \
    curl -fsSL --retry 3 "https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_linux_amd64.tar.gz" -o /tmp/grype.tar.gz && \
    echo "${GRYPE_SHA256}  /tmp/grype.tar.gz" | sha256sum -c - && \
    tar -xzf /tmp/grype.tar.gz -C /usr/local/bin grype

FROM gcr.io/distroless/static-debian12:nonroot
LABEL org.opencontainers.image.source="https://github.com/PedDavid/secops"
LABEL org.opencontainers.image.description="Syft package and Grype vulnerability comparisons for Renovate digest updates"
COPY --from=builder --chown=1000:65534 /cache /var/cache/digest-diff
COPY --from=tools /usr/local/bin/syft /usr/local/bin/grype /usr/local/bin/
COPY --from=builder /digest-diff /usr/local/bin/digest-diff
USER 1000:65534
ENV CACHE_DIR=/var/cache/digest-diff PORT=8080 HOME=/tmp
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/digest-diff"]

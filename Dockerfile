FROM golang:1.26-bookworm AS builder
WORKDIR /app
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /digest-diff .

FROM debian:bookworm-slim
ARG SYFT_VERSION=1.44.0
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates curl && \
    curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh \
      | sh -s -- -b /usr/local/bin "v${SYFT_VERSION}" && \
    apt-get remove -y curl && \
    apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/*
RUN useradd -r -u 1000 -g nogroup digest-diff && \
    mkdir -p /var/cache/digest-diff && \
    chown digest-diff:nogroup /var/cache/digest-diff
COPY --from=builder /digest-diff /usr/local/bin/digest-diff
USER digest-diff
ENV CACHE_DIR=/var/cache/digest-diff
ENV PORT=8080
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/digest-diff"]

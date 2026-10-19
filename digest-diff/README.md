# digest-diff

HTTP service that diffs package lists between two container image digests using [syft](https://github.com/anchore/syft), caches results, and serves an HTML report and SVG badge.

Built to surface what actually changed in Renovate digest-only MRs, where the tag stays the same but the underlying OS packages shift.

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/diff?old=<ref>&new=<ref>` | HTML report (blocks until computed) |
| `GET` | `/diff.json?old=<ref>&new=<ref>` | Same result as JSON |
| `GET` | `/badge?old=<ref>&new=<ref>` | SVG badge; returns `pending` if not yet cached |
| `POST` | `/jobs?old=<ref>&new=<ref>` | Enqueue a diff in the background; returns 202 |
| `GET` | `/healthz` | Liveness/readiness probe |

Image references use the standard `image@sha256:<digest>` format, e.g.:

```
GET /diff?old=postgres:18@sha256:abc...&new=postgres:18@sha256:def...
```

## How it works

1. On first request for a digest pair, the service runs `syft scan` against both images.
2. Package lists are diffed by `(name, type)` — added, removed, and version-changed packages are recorded.
3. The result is written to a local cache directory (keyed by SHA-256 of the digest pair).
4. Subsequent requests for the same pair are served directly from cache. Digests are immutable so the cache never invalidates.

Concurrent requests for the same pair are deduplicated — syft runs once regardless of how many callers are waiting.

## Renovate integration

Add to `renovate.json` to pre-generate reports at PR creation time:

```json
"postUpgradeTasks": {
  "commands": [
    "curl -sf -X POST 'http://digest-diff/jobs?old={{depName}}@{{currentDigest}}&new={{depName}}@{{newDigest}}' || true"
  ],
  "fileFilters": [],
  "executionMode": "branch"
},
"allowedPostUpgradeCommands": [
  "curl -sf -X POST 'http://digest-diff/jobs.*'"
]
```

Then reference the badge in `prBodyDefinitions`:

```json
"prBodyDefinitions": {
  "DigestDiff": "[![packages](http://digest-diff/badge?old={{depName}}@{{currentDigest}}&new={{depName}}@{{newDigest}})](http://digest-diff/diff?old={{depName}}@{{currentDigest}}&new={{depName}}@{{newDigest}})"
}
```

## Running locally

```sh
CACHE_DIR=/tmp/digest-diff-cache PORT=8080 go run .
```

Requires `syft` on `$PATH` — install with:

```sh
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
```

## Docker

```sh
docker build -t digest-diff .
docker run -p 8080:8080 -v digest-diff-cache:/var/cache/digest-diff digest-diff
```

The `SYFT_VERSION` build arg pins the syft release baked into the image (default `1.44.0`).

## Kubernetes

```sh
kubectl apply -f k8s/
```

The manifests deploy a single replica with a `ReadWriteOnce` PVC for the cache. The pod runs as non-root with a read-only root filesystem.

## Configuration

| Env var | Default | Description |
|---------|---------|-------------|
| `PORT` | `8080` | Listening port |
| `CACHE_DIR` | `/var/cache/digest-diff` | Directory for cached diff results |

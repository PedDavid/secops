# digest-diff

Compare packages and known vulnerabilities between two public container image digests.
Syft inventories each image once; Grype scans the retained native SBOMs. Reports and
badges explain Renovate digest-only merge requests. Vulnerability results are informational;
the service does not block merges or monitor deployed workloads.

The current deployment targets **linux/amd64**, public registries, and one replica.
No Docker socket, registry credentials, or Kubernetes API access is needed at runtime.

## Reports and jobs

All comparison endpoints require `old` and `new` query parameters in
`image@sha256:<64 lowercase hex characters>` form. Tags without digests and local file
sources are rejected. An optional tag before `@sha256:` is accepted.

| Method | Path | Behavior |
|---|---|---|
| GET | `/diff` | Immediate HTML page with live stages, early package results, and final vulnerability results |
| GET | `/diff.json` | Same report as JSON, retaining `added`, `removed`, `changed` fields |
| GET | `/badge` | Vulnerability change counts, or not scanned / queued / running / failed / stale |
| POST | `/jobs` | Submit or retry; 202 for accepted jobs, 200 for a fresh cached report |
| GET | `/jobs` | Recent job state and failure status; 404 if no known job/report |
| GET | `/healthz` | HTTP process and initialized scanner binaries are available |

The HTML page starts or joins a background job automatically. It polls for stage updates,
shows package changes before vulnerability matching finishes, and updates in place when
complete. Failures and full queues show a retry button; package results remain visible
if vulnerability analysis fails. Fresh cached reports render immediately. JavaScript is
required for live updates; a link to the blocking JSON report is provided as a fallback.

For API clients, prefer asynchronous jobs: submit with POST, poll GET `/jobs`, and fetch the report
when completed. Job status includes `stage` and `packages_ready`. The HTML client uses
`GET /diff?fragment=1&old=...&new=...` for nonblocking report fragments: 202 for partial
or unavailable content, 200 for the complete fresh report. Fragments never start a job. A full queue returns 503 with `Retry-After`. GET `/diff` also submits
work; a disconnected client does not cancel the shared job. GET `/diff.json` continues to wait
for the completed report on a cache miss. Health does not establish
registry connectivity or database freshness: verify those with a real comparison.

Reports show introduced, resolved, and persisting **package/vulnerability matches**,
severity, fix status/versions, platform, scanner versions, database metadata, and scan time.
Findings are matched by vulnerability ID + namespace + package name + package type;
installed version is excluded so vulnerable upgrades can remain persisting. Duplicate
matches for the same installed version are collapsed. Counts are package findings, not
unique CVEs. Package diffs compare sorted version sets when several versions of the
same name/type occur, displayed as comma-separated versions. Aliases from different advisory namespaces are not merged. A resolved finding
means it is no longer matched; a distro change can also change advisory identity.

## Storage and freshness

- Full Syft JSON SBOMs are keyed by image reference, platform, and Syft version.
  Distro metadata, locations, PURLs, and other native fields are retained for Grype.
- Grype checks for a database update before each new comparison. Both images use that
  same snapshot, with automatic updates disabled during matching. TLS, archive checksum,
  installed-database hash, and database-age validation remain enabled.
- Findings are cached by SBOM identity, Grype version, database identity, and matching
  policy version. A new database snapshot triggers matching again without pulling images.
- Reports expire after `SCAN_TTL` (default 6h). A later request or POST recomputes them.
  Expiry is request-driven; no background polling or scheduled monitoring is included.
- Badges have a short cache lifetime; stale reports never appear as fresh results.
- A database update or scan failure fails the job rather than reporting zero findings.

The PVC retains SBOMs, findings, reports, and the database. Recent job state is held in
memory (at most 128 entries) and is lost on restart. Resubmit interrupted jobs after a
restart; retained artifacts are reused. One worker processes jobs with eight queue slots;
`SCAN_TIMEOUT` starts when a job begins running, excluding queue wait.

Caches do not currently have automatic eviction. Monitor PVC capacity; stop the deployment
before pruning `sboms/`, `findings/`, or `reports/` if necessary. All can be regenerated.
Do not share the database directory with another replica or an external updater.

## Build and publish to GHCR

The repository workflow `.github/workflows/digest-diff.yml` runs race tests, vet, and
format checks, then builds the amd64 image and runs a live comparison in a read-only, non-root
container before publishing. The live check requires public registry and database access. Pushes to `main` publish:

- `ghcr.io/peddavid/secops/digest-diff:main`
- `ghcr.io/peddavid/secops/digest-diff:sha-<full-git-commit>`

PRs build and smoke-test without publishing. Manual runs publish only when run against `main`.
The workflow uses GitHub's `GITHUB_TOKEN` with `packages: write`; no PAT is required.
After the first publish, **set the GHCR package visibility to public** so your cluster
can pull without credentials. Existing package permissions may need to grant this
repository Actions write access. Publishing the image does not deploy to Kubernetes.

The Dockerfile pins Syft 1.54.1 and Grype 0.120.1 and verifies release SHA-256 checksums.
When upgrading a tool, update its version and corresponding checksum together from
the official release. The image carries an OCI source label linking it to this repository.

For build networks with a trusted TLS-intercepting proxy, the Dockerfile accepts an
optional BuildKit secret `--secret id=build_ca,src=/path/to/trusted-ca-bundle.pem`.
It is used only for download verification during the build and is not copied into the image.

Local build from `digest-diff/`:

```sh
docker build --platform linux/amd64 -t ghcr.io/peddavid/secops/digest-diff:dev .
```

## Deploy to Kubernetes

For a configurable Helm installation, use the [Helm chart](charts/digest-diff/README.md):

```sh
# From the repository root:
helm upgrade --install digest-diff ./digest-diff/charts/digest-diff \
  --namespace secops --create-namespace --wait --timeout 5m
```

It supports custom storage, image tags/digests, resources, scheduling, and optional ingress.
The existing Kustomize manifests remain an alternative; choose one deployment method.
See the chart's migration steps if those resources are already installed.


Requires an amd64 Linux node and a default StorageClass supporting a 5Gi ReadWriteOnce
PVC. Customize `k8s/pvc.yaml` if you need an explicit StorageClass or more space.
Use one replica; Recreate updates avoid simultaneous database writers and RWO mount
conflicts. Allow roughly 2Gi memory and 4Gi temporary disk for scanning; larger images
may need higher limits or a longer timeout.

From `digest-diff/`, after the image is published:

```sh
kubectl apply -k k8s/
kubectl -n secops rollout status deployment/digest-diff --timeout=180s
kubectl -n secops logs deployment/digest-diff
```

The default manifest follows `:main` with `imagePullPolicy: Always`. For repeatable
rollouts, add an `images` entry to `k8s/kustomization.yaml` before applying:

```yaml
images:
  - name: ghcr.io/peddavid/secops/digest-diff
    newTag: sha-REPLACE_WITH_FULL_PUBLISHED_COMMIT
```

A new mutable `:main` image alone does not restart existing pods. Prefer the immutable
commit tag for subsequent updates.

The service is available inside the cluster at `http://digest-diff.secops.svc.cluster.local`.
Use your own authenticated ingress or VPN to expose reports to your browser. This service
has no built-in authentication: keep it on a trusted network. Image-reference validation
prevents local filesystem scan sources but is not a network isolation boundary. Untrusted
callers can request registry downloads; use ingress controls and egress policies accordingly.
No ingress is created automatically.

For a local smoke check:

```sh
kubectl -n secops port-forward service/digest-diff 8080:80
```

In another terminal, set two real public image references and submit a comparison:

```sh
OLD='docker.io/library/alpine@sha256:REPLACE_WITH_OLD_DIGEST'
NEW='docker.io/library/alpine@sha256:REPLACE_WITH_NEW_DIGEST'
curl --fail-with-body -X POST -G http://127.0.0.1:8080/jobs \
  --data-urlencode "old=$OLD" --data-urlencode "new=$NEW"
curl --fail-with-body -G http://127.0.0.1:8080/jobs \
  --data-urlencode "old=$OLD" --data-urlencode "new=$NEW"
# Repeat the status request until completed; investigate logs if failed.
curl --fail-with-body -G http://127.0.0.1:8080/diff.json \
  --data-urlencode "old=$OLD" --data-urlencode "new=$NEW"
```

For an automated check against the forwarded service, run `python3 scripts/smoke.py`
(the defaults compare two pinned Alpine images). You can pass `--url`, `--old`, and `--new`.

Verify `scan.platform`, database metadata, and all three vulnerability sections in the
returned JSON. On a second request, `scan.scanned_at` should be unchanged while fresh.
The first run downloads the vulnerability database and image layers and can take minutes.

Outbound HTTPS is required to `grype.anchore.io` and the registries you scan, including
their authentication and layer/CDN endpoints. Docker Hub commonly uses `registry-1.docker.io`,
`auth.docker.io`, `index.docker.io`, and layer CDNs. Nodes also need access to `ghcr.io` and its layer endpoints
to pull the service image. Preserve DNS and normal TLS trust. There is no need to mirror
the vulnerability database for this initial deployment.

## Renovate integration

In self-hosted Renovate's **administrator configuration**, allow only the intended job
submission command using `allowedCommands` (current Renovate name). Do not place that
administrator setting in repository configuration. Check your installed Renovate version
if migrating from the older `allowedPostUpgradeCommands` setting.

Example repository configuration for digest-pinned Docker dependencies:

```json
{
  "packageRules": [{
    "matchDatasources": ["docker"],
    "matchUpdateTypes": ["digest"],
    "postUpgradeTasks": {
      "commands": [
        "curl --fail-with-body --max-time 15 -X POST -G 'http://digest-diff.secops.svc.cluster.local/jobs' --data-urlencode 'old={{depName}}@{{currentDigest}}' --data-urlencode 'new={{depName}}@{{newDigest}}'"
      ],
      "fileFilters": [],
      "executionMode": "update"
    }
  }],
  "prBodyDefinitions": {
    "DigestDiff": "[![digest diff](https://YOUR_REPORT_HOST/badge?old={{depName}}%40{{currentDigest}}&new={{depName}}%40{{newDigest}})](https://YOUR_REPORT_HOST/diff?old={{depName}}%40{{currentDigest}}&new={{depName}}%40{{newDigest}})"
  },
  "prBodyColumns": ["Package", "Update", "Change", "DigestDiff"]
}
```

Use an administrator-controlled wrapper script for job submission if dependency names
can come from untrusted contributors; interpolated shell commands need careful validation.
Some Git hosts proxy or cache badge images and cannot reach private report hosts. The report
link remains useful over VPN, but automatic badge updates depend on the host's image proxy.
This integration is optional and is not exercised by the Go tests.

## Configuration and development

| Variable | Default | Purpose |
|---|---|---|
| `CACHE_DIR` | `/var/cache/digest-diff` | Writable persistent directory |
| `PORT` | `8080` | HTTP listener |
| `SCAN_TTL` | `6h` | Freshness of completed reports |
| `SCAN_TIMEOUT` | `15m` | Maximum running time per comparison |

Syft and Grype matching configuration is owned by the application; ambient `SYFT_*` /
`GRYPE_*` settings and external config files do not alter it. Change the explicit scanner
configuration and bump `scanPolicy` when changing matching behavior.

With Go 1.26+, pinned `syft` and `grype` on PATH, from `digest-diff/`:

```sh
go test -race ./...
go vet ./...
CACHE_DIR=/tmp/digest-diff-cache go run .
```

An opt-in live integration test exercises the complete scanner and HTTP workflow against
real image digests; it needs network access and downloads the database:

```sh
DIGEST_DIFF_LIVE=1 DIGEST_DIFF_OLD="$OLD" DIGEST_DIFF_NEW="$NEW" \
  go test -run TestLiveComparison -v -timeout 20m
```

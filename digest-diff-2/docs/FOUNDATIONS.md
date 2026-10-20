# Shared application foundations

This is a separate Rust application in `secops/digest-diff-2`. The original Go
`digest-diff` remains independently deployable. No changes are made to the three
reference repositories.

Sources inspected for this implementation:

| Project | Inspected commit | Foundation carried forward |
|---|---|---|
| [clavium](https://github.com/PedDavid/clavium) | `07f5f9889de1cd5071b51d45227bf9293d2bf388` | Axum/Askama, OIDC sessions, separate ops port, versioned image/chart releases |
| [dominium](https://github.com/PedDavid/dominium) | `7603342b78c2c118b8c9a97c4220cd58aaf6c7a6` | Inventory-style UI, themes/palettes, Prometheus and Kubernetes operating conventions |
| [lastmile](https://github.com/PedDavid/lastmile) | `d1e4eafde86bd96c27d336476ad1d473ce2a102e` | SQLite durability, OIDC/CSRF implementation and signed-provider tests, embedded Basecoat/Tailwind/htmx assets |

`src/web/auth.rs`, `src/duration.rs`, and `tests/oidc.rs` are adapted from Lastmile,
with application names, configuration, routes and state wiring changed. The UI
uses the same vendored Basecoat and htmx assets, theme tokens and checked-in
Tailwind stylesheet, retaining their license files. Tailwind can be rebuilt with
its standalone CLI using `make css`; no Node.js is needed to build or run the
application. `assets/diff.css` holds digest-specific layout over that foundation.

## Architecture

- **Web:** Axum on 8080, Askama templates and htmx fragments. An index supports
  search and submission; reports show package changes before vulnerability scans
  finish. Themes and palettes persist in cookies.
- **Identity:** OIDC authorization code + PKCE, verified ID-token signature,
  issuer/audience/expiry, state and nonce; encrypted private session cookies;
  browser POSTs require Origin and CSRF checks. Signed mock-provider tests cover
  login and state rejection. Administrators submit/retry; members read reports.
- **Automation:** a separately configured file-backed bearer token permits
  Renovate to submit and read comparisons without browser cookies. Never put
  tokens in query strings. Badge visibility is independently configurable.
- **State:** SQLite WAL stores job state, partial packages and completed reports.
  The worker's eight queue slots remain bounded. Restarted unfinished jobs are
  marked interrupted, retaining partial inventory; a retry reuses scanner caches.
- **Inventory:** complete native Syft JSON cached per reference, platform and
  Syft version. Grype consumes those SBOMs; matching uses one database snapshot
  per pair. Findings are cached separately by SBOM, Grype and database identity.
- **Operations:** `/healthz`, database-backed `/readyz` and OpenMetrics on 9090,
  through a separate ClusterIP Service. ServiceMonitor, alert rules and a Grafana
  dashboard are optional chart resources. No Kubernetes API access or RBAC is needed.
- **Distribution:** distinct GHCR application image and OCI Helm chart. Semantic
  app/chart versions are published once; changing a released version requires a bump.

No CRD or Kubernetes inventory controller was copied: those solve the inventory
problems in Clavium and Dominium, while this application's inputs remain image
references from Renovate or a user.

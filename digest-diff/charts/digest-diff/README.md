# digest-diff Helm chart

Install from a checkout of [PedDavid/secops](https://github.com/PedDavid/secops):

```sh
helm upgrade --install digest-diff ./digest-diff/charts/digest-diff \
  --namespace secops --create-namespace --wait --timeout 5m
```

The chart defaults to the first published amd64 image's immutable commit tag, a single
replica, Recreate updates, a 5Gi PVC using the default StorageClass, and a ClusterIP
service. It retains the non-root, read-only filesystem and restricted container privileges.
A writable temporary volume is mounted separately. The service does not use the Kubernetes API.
The namespace is managed by Helm's `--create-namespace`, not by the chart.

For subsequent image releases, set `image.tag` to the published `sha-<full-commit>` tag,
or set `image.digest=sha256:...` to pin a registry manifest digest (takes precedence over tag).
The chart version and image version are independent.

Create a homelab values file, for example:

```yaml
persistence:
  storageClass: YOUR_STORAGE_CLASS
  size: 10Gi
resources:
  requests:
    cpu: 250m
    memory: 512Mi
  limits:
    cpu: "2"
    memory: 2Gi
# Optional; secure access through your ingress controller or VPN.
ingress:
  enabled: true
  className: nginx
  hosts:
    - host: digest-diff.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: digest-diff-tls
      hosts: [digest-diff.example.com]
```

Then add `-f homelab-values.yaml` to the install command. The ingress controller and TLS
Secret must already exist or be provisioned separately. Authentication is handled by your
ingress/VPN; the application itself has none. For nginx, long synchronous `/diff` requests
may need controller timeout annotations; prefer submitting `/jobs` and polling its status.

All defaults are documented in [values.yaml](values.yaml). Other supported settings include:

| Setting | Default | Purpose |
|---|---|---|
| `scan.ttl` | `6h` | Report freshness; recompute on next request after expiry |
| `scan.timeout` | `15m` | Maximum running time per comparison |
| `persistence.existingClaim` | empty | Mount an existing PVC instead of creating one |
| `persistence.keep` | `true` | Retain generated PVC on uninstall |
| `persistence.enabled` | `true` | Set false for ephemeral development storage |
| `persistence.storageClass` | `null` | Default StorageClass; explicit `""` selects no class |
| `tmpSizeLimit` | `4Gi` | Temporary image extraction space |
| `service.port` | `80` | ClusterIP service port |
| `imagePullSecrets` | `[]` | Optional Kubernetes image pull Secret references |
| `nodeSelector` | Linux/amd64 | Scheduling constraints; ARM images are not supported |
| `tolerations`, `affinity` | empty | Additional scheduling controls |
| `podAnnotations` | `{}` | Pod metadata for operational integrations |

Keep one replica: the database directory must have a single writer. No replica-count or
autoscaling setting is exposed. Do not install two releases against the same cache PVC.
To expand a PVC, the StorageClass must support expansion; changing classes requires a new
claim. Cache contents are regenerable, but inspect storage before deleting anything.

## Existing manifest deployment

Do not install Helm over the existing `k8s/` resources with the same names: Helm does not
own those resources. To migrate while preserving the existing cache:

1. Scale the old Deployment to zero and wait for its pod to terminate.
2. Install a differently named release, such as `digest-diff-helm`, in the **same namespace**,
   with `--set persistence.existingClaim=digest-diff-cache`.
3. Verify a real comparison and update Renovate/report routing to the new Service.
4. Remove the old Deployment and Service after migration. Keep the shared PVC.

## Validate and operate

```sh
helm lint --strict ./digest-diff/charts/digest-diff
helm template digest-diff ./digest-diff/charts/digest-diff --namespace secops
kubectl -n secops rollout status deployment/digest-diff
kubectl -n secops port-forward service/digest-diff 8080:80
# In another terminal, run the real scan check from the repository root:
python3 digest-diff/scripts/smoke.py
```

Helm `--wait` confirms Kubernetes readiness. A real comparison is needed to verify registry
and vulnerability-database connectivity. See the application README for network destinations
and report semantics.

On uninstall, the generated PVC is retained by default. Reinstall with
`--set persistence.existingClaim=digest-diff-cache` to reuse it. If you used a different
release name or a name override, use that release's actual PVC name from `kubectl get pvc`.

The chart workflow lints, renders, and packages `digest-diff-0.1.0.tgz` as the
`digest-diff-helm-chart` Actions artifact. You can install a downloaded package with
`helm upgrade --install digest-diff ./digest-diff-0.1.0.tgz -n secops --create-namespace --wait`.
No Helm repository or OCI chart publication is configured yet; GHCR contains the application image.

# Flux Instance Reference

Flux Operator chart **v0.45.0**, Flux distribution **v0.30.0**.

---

## What it does

Deploys a full Flux installation via the flux-operator. Syncs from `https://github.com/chkpwd/iac` at `kubernetes/flux`, branch `main`, every hour. The GitHub receiver at `flux-webhook.chkpwd.com` lets GitHub push webhooks to trigger immediate syncs on push.

---

## Components

Only the four core controllers are enabled — image automation excluded:

- `source-controller` — fetches Git/Helm/OCI sources
- `kustomize-controller` — applies Kustomizations
- `helm-controller` — reconciles HelmReleases
- `notification-controller` — handles receivers and alerts

---

## Kustomize patches

### Concurrency

`kustomize-controller`, `helm-controller`, and `source-controller` all get:

```
--concurrent=10
--requeue-dependency=5s
```

`kustomize-controller` additionally gets `--concurrent=20` (overrides the first patch for that controller). Dependency requeue at 5s means reconciliation chains resolve faster after a dependency becomes ready.

### Memory limits

All three controllers get a `2Gi` memory limit. Needed for large Helm chart renders and kustomize builds with many resources.

### In-memory kustomize builds

```
--concurrent=20
temp volume: emptyDir(medium: Memory)
```

kustomize-controller builds kustomizations in a RAM-backed tmpfs instead of disk. Faster builds, nothing persisted between runs.

### Helm repository caching (source-controller)

```
--helm-cache-max-size=10
--helm-cache-ttl=60m
--helm-cache-purge-interval=5m
```

Caches up to 10 Helm repository indexes in memory for 60 minutes. Avoids re-fetching index.yaml on every reconcile.

### OOM watch (helm-controller)

```
--feature-gates=OOMWatch=true
--oom-watch-memory-threshold=95
--oom-watch-interval=500ms
```

helm-controller watches its own memory use every 500ms. If it hits 95% of the limit it cancels the current Helm operation cleanly rather than getting OOM-killed mid-apply.

### Cancel health checks on new revision (kustomize-controller)

```
--feature-gates=CancelHealthCheckOnNewRevision=true
```

If a new commit lands while kustomize-controller is still doing health checks on the previous apply, it cancels and starts fresh. Avoids stale health check state blocking a new deployment.

### Config watch label selector

```
--watch-configs-label-selector=owner!=helm
```

Both helm-controller and kustomize-controller watch ConfigMaps/Secrets for changes, but exclude ones owned by Helm releases (to avoid spurious reconciles from Helm writing its own objects).

---

## HelmRelease component defaults (`components/kustomization.yml`)

Applied as a Kustomize patch to every HelmRelease in the cluster:

| Setting                                    | Value            | Effect                                                    |
| ------------------------------------------ | ---------------- | --------------------------------------------------------- |
| `driftDetection.mode`                      | `enabled`        | Detects out-of-band changes to Helm-managed resources     |
| `install.crds`                             | `CreateReplace`  | Creates or replaces CRDs on install                       |
| `install.strategy.name`                    | `RetryOnFailure` | Retries failed installs automatically                     |
| `rollback.cleanupOnFail`                   | `true`           | Deletes failed resources on rollback                      |
| `rollback.recreate`                        | `true`           | Recreates resources that can't be patched during rollback |
| `timeout`                                  | `10m`            | Per-release timeout                                       |
| `upgrade.cleanupOnFail`                    | `true`           | Deletes failed resources on upgrade failure               |
| `upgrade.crds`                             | `CreateReplace`  | Updates CRDs on upgrade                                   |
| `upgrade.remediation.retries`              | `2`              | Retries up to 2 times before giving up                    |
| `upgrade.remediation.remediateLastFailure` | `true`           | Applies remediation even after the last retry             |

---

## Alerting

Two PrometheusRules fire critical alerts:

- `FluxInstanceAbsent` — `flux_instance_info` metric gone for 5m (Flux itself is down)
- `FluxInstanceNotReady` — instance exists but `ready != "True"` for 5m

---

## Troubleshooting

```bash
# Check Flux component status
flux check

# Watch reconciliation
flux get all -A

# Force a sync
flux reconcile source git chkpwd-ops
flux reconcile kustomization chkpwd-ops

# Check webhook receiver URL (for GitHub webhook config)
kubectl -n flux-system get receiver github-receiver -o jsonpath='{.status.webhookPath}'
```

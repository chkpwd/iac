# Prometheus (kube-prometheus-stack) Reference

Helm chart **kube-prometheus-stack v82.15.1**.

---

## What it does

Deploys Prometheus, Alertmanager, node-exporter, kube-state-metrics, and the Prometheus operator. Grafana is disabled (managed separately via grafana-operator). Metrics stored in `ceph-block` PVCs.

---

## Prometheus

### Image

Uses `prompp/prompp` instead of the upstream Prometheus image. `prompp` is a hardened build that drops privileges — hence the explicit `runAsUser: 64535` / `runAsGroup: 64535` security context.

### Storage

| Setting            | Value        |
| ------------------ | ------------ |
| `storageClassName` | `ceph-block` |
| `storage`          | 10Gi         |
| `retention`        | 14d          |
| `retentionSize`    | 8GB          |

Retention is dual — whichever limit hits first triggers pruning.

### Features

| Feature flag                    | Effect                                                   |
| ------------------------------- | -------------------------------------------------------- |
| `auto-gomaxprocs`               | Sets GOMAXPROCS from cgroup CPU quota automatically      |
| `memory-snapshot-on-shutdown`   | Writes a WAL snapshot on clean shutdown — faster restart |
| `new-service-discovery-manager` | Reloads service discovery configs without full restart   |

`walCompression: true` — compresses the write-ahead log, reduces disk use ~30-40%.

### Selector nil = all

All four selector flags are set to `false`:

```text
podMonitorSelectorNilUsesHelmValues: false
probeSelectorNilUsesHelmValues: false
ruleSelectorNilUsesHelmValues: false
scrapeConfigSelectorNilUsesHelmValues: false
serviceMonitorSelectorNilUsesHelmValues: false
```

This makes Prometheus pick up ServiceMonitors, PodMonitors, PrometheusRules, and ScrapeConfigs from **all namespaces** without requiring a matching label. Without this, only resources labeled to match the Helm release would be scraped.

### Resources

```text
requests: 100m CPU
limits:   2000Mi memory
```

No CPU limit — CPU is burstable, memory is capped.

---

## Alertmanager

Stores alerts in a 1Gi `ceph-block` PVC. External URL `https://alertmanager.chkpwd.com`.

### Routing (`AlertmanagerConfig`)

```text
groupBy: [alertname, job]
groupWait: 1m       # wait before sending first notification
groupInterval: 10m  # wait before sending update on ongoing alert
repeatInterval: 12h # re-notify if still firing
```

Routes all `severity: critical` alerts to Pushover. `InfoInhibitor` alerts are silenced (sent to `null` receiver). Critical inhibits warning for the same alertname+namespace.

### Pushover

- HTML formatting enabled
- Priority `1` (high) when firing, `0` (normal) when resolved
- Sound: `mgs-alert`
- TTL: 86400s (Pushover notification expires after 24h)
- `sendResolved: true`

---

## Scraped components

| Component               | Enabled | Notes                                                                    |
| ----------------------- | ------- | ------------------------------------------------------------------------ |
| `kubeApiServer`         | yes     | High-cardinality buckets dropped via `metricRelabelings`                 |
| `kubelet`               | yes     | `uid`, `id`, `name` labels dropped; rest_client duration buckets dropped |
| `kubeStateMetrics`      | yes     | —                                                                        |
| `nodeExporter`          | yes     | —                                                                        |
| `kubeControllerManager` | **no**  | Not accessible from Prometheus in this setup                             |
| `kubeEtcd`              | **no**  | Same                                                                     |
| `kubeProxy`             | **no**  | kube-proxy not running (Cilium replaces it)                              |
| `kubeScheduler`         | **no**  | Not accessible                                                           |

### Metric relabeling rationale

The dropped metrics (`apiserver_request_duration_seconds_bucket`, `rest_client_request_duration_seconds_*`, etc.) are high-cardinality histograms that balloon TSDB size without much operational value for this setup.

---

## Custom alert rules

### `DockerhubRateLimitRisk`

```text
count(time() - container_last_seen{image=~"(docker.io).*",container!=""} < 30) > 100
```

Fires critical if more than 100 containers are pulling from `docker.io` in a 30-second window — likely to hit the rate limit.

### `OomKilled`

```text
(kube_pod_container_status_restarts_total offset 10m >= 1)
AND min_over_time(kube_pod_container_status_last_terminated_reason{reason="OOMKilled"}[10m]) == 1
```

Fires critical if a container restarted and the last termination reason was OOMKilled, within the last 10 minutes.

---

## Grafana integration

Grafana is not deployed by this chart (`grafana.enabled: false`), but dashboard ConfigMaps are still deployed (`forceDeployDashboards: true`). The grafana-operator picks them up via:

```text
label: dashboards=external-grafana
searchNamespace: ALL
grafana_folder: Kubernetes
```

---

## Troubleshooting

```bash
# Check Prometheus targets
kubectl -n monitoring port-forward svc/prometheus-operated 9090:9090
# then open http://localhost:9090/targets

# Check Alertmanager config
kubectl -n monitoring port-forward svc/alertmanager-operated 9093:9093

# Check PrometheusOperator logs
kubectl -n monitoring logs deploy/prometheus-prometheus-operator

# Check if a ServiceMonitor is being picked up
kubectl -n monitoring get servicemonitors -A
```

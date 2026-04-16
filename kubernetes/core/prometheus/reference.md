## Prometheus (kube-prometheus-stack) Reference

Helm chart **kube-prometheus-stack v83.4.3**.

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

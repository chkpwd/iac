## Prometheus (kube-prometheus-stack) Reference

Helm chart **kube-prometheus-stack v87.3.0**.

---

## What it does

Deploys Prometheus, Alertmanager, node-exporter, kube-state-metrics, and the Prometheus operator. Grafana is disabled (managed separately via grafana-operator). Metrics stored in `ceph-block` PVCs.

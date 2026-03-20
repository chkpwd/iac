# CoreDNS Reference

Helm chart **v1.45.2**.

---

## What it does

Replaces the default in-cluster DNS with a custom CoreDNS deployment. Runs on control-plane nodes only (via affinity + tolerations), serving cluster DNS at `10.96.0.10`.

---

## Key values

### Identity / compatibility

| Value                 | Setting      | Effect                                                                 |
| --------------------- | ------------ | ---------------------------------------------------------------------- |
| `fullnameOverride`    | `coredns`    | Resource names use `coredns` instead of the release name               |
| `k8sAppLabelOverride` | `kube-dns`   | Pods get `k8s-app: kube-dns` label — kubelet finds them via this label |
| `service.name`        | `kube-dns`   | Service named `kube-dns` as expected by Kubernetes                     |
| `service.clusterIP`   | `10.96.0.10` | Fixed ClusterIP — matches what kubeadm sets in kubelet config          |
| `replicaCount`        | `2`          | Two replicas for basic HA                                              |

### Corefile plugins

The `servers` block builds the Corefile directly.

| Plugin                         | Config                                | Effect                                                                              |
| ------------------------------ | ------------------------------------- | ----------------------------------------------------------------------------------- |
| `errors`                       | —                                     | Logs DNS errors                                                                     |
| `health`                       | `lameduck 5s`                         | `/health` endpoint; 5s delay on shutdown before marking unhealthy                   |
| `ready`                        | —                                     | `/ready` endpoint — pod only becomes ready when all plugins report ready            |
| `log`                          | `class error`                         | Logs only error-class queries (not all queries)                                     |
| `prometheus`                   | `0.0.0.0:9153`                        | Exposes metrics on port 9153 for scraping                                           |
| `kubernetes`                   | `cluster.local in-addr.arpa ip6.arpa` | Resolves `.cluster.local` names and reverse DNS                                     |
| `kubernetes` → `pods verified` | —                                     | Only resolves pod IPs that actually exist in the API (not synthetic)                |
| `kubernetes` → `fallthrough`   | `in-addr.arpa ip6.arpa`               | Passes reverse DNS queries upstream if not resolved locally                         |
| `autopath`                     | `@kubernetes`                         | Rewrites search-domain queries server-side to reduce DNS RTTs                       |
| `forward`                      | `. /etc/resolv.conf`                  | External DNS forwarded to node's resolvers                                          |
| `cache`                        | `prefetch 20` / `serve_stale`         | Cache with prefetch on the 20th-to-last TTL second; serve stale on upstream failure |
| `loop`                         | —                                     | Detects and halts forwarding loops                                                  |
| `reload`                       | —                                     | Auto-reloads Corefile on change without restart                                     |
| `loadbalance`                  | —                                     | Round-robins A/AAAA responses                                                       |

### Placement

Pinned to control-plane nodes:

```yaml
affinity:
  nodeAffinity:
    requiredDuringSchedulingIgnoredDuringExecution:
      nodeSelectorTerms:
        - matchExpressions:
            - key: node-role.kubernetes.io/control-plane
              operator: Exists
tolerations:
  - key: CriticalAddonsOnly
    operator: Exists
  - key: node-role.kubernetes.io/control-plane
    operator: Exists
    effect: NoSchedule
```

DNS runs on control-plane so it's isolated from workload churn on worker nodes.

---

## Troubleshooting

```bash
# Check CoreDNS pods
kubectl -n kube-system get pods -l k8s-app=kube-dns

# Tail logs (errors only by config)
kubectl -n kube-system logs -l k8s-app=kube-dns

# Test resolution from a pod
kubectl run -it --rm dnstest --image=busybox --restart=Never -- nslookup kubernetes.default

# Check metrics
kubectl -n kube-system port-forward svc/coredns-metrics 9153:9153
```

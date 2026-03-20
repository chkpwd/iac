# Spegel Reference

Helm chart **v0.2.0**.

---

## What it does

Spegel is a peer-to-peer OCI registry mirror. Instead of every node pulling the same image from a remote registry, nodes share image layers with each other via a local p2p mesh. Reduces external pull traffic and speeds up node-to-node image distribution.

---

## How it works

Each node runs a Spegel daemon that:

1. Intercepts containerd image pulls via the registry mirror config
2. Checks if any other node in the cluster already has the requested layer
3. Serves it locally if found, falls through to the upstream registry if not

No central component — fully distributed.

---

## Key values

| Value                                 | Setting                           | Effect                                                                                                             |
| ------------------------------------- | --------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| `spegel.appendMirrors`                | `true`                            | Adds Spegel as an additional mirror rather than replacing existing ones — upstream registry still used as fallback |
| `spegel.containerdSock`               | `/run/containerd/containerd.sock` | Socket path for the containerd API (standard Talos/k8s path)                                                       |
| `spegel.containerdRegistryConfigPath` | `/etc/cri/conf.d/hosts`           | Where Spegel writes containerd registry mirror configs (Talos-specific path)                                       |
| `service.registry.hostPort`           | `29999`                           | Local port Spegel listens on for image pulls — containerd mirror config points here                                |
| `serviceMonitor.enabled`              | `true`                            | Prometheus scrapes Spegel metrics                                                                                  |
| `grafanaDashboard.enabled`            | `true`                            | Deploys a Grafana dashboard ConfigMap                                                                              |

### `appendMirrors: true`

This is important — it means existing mirror configs (e.g. a local registry proxy) are preserved and Spegel is appended. If set to `false`, Spegel would overwrite any other mirror config on the node.

---

## Troubleshooting

```bash
# Check Spegel pods (runs as DaemonSet)
kubectl -n spegel get pods -o wide

# Check if mirror config was written on a node
# (SSH to node)
cat /etc/cri/conf.d/hosts/<registry>/hosts.toml

# Check Spegel logs on a specific node
kubectl -n spegel logs <spegel-pod>

# Verify pulls are being served locally (check metrics)
kubectl -n spegel port-forward svc/spegel 5000:5000
curl http://localhost:5000/metrics | grep spegel_

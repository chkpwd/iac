# Rook-Ceph Reference

Helm charts **rook-ceph v1.19.2** (operator) + **rook-ceph-cluster v1.19.2** (cluster).

---

## What it does

Rook manages a Ceph cluster using NVMe drives across all nodes. Provides a single `ceph-block` StorageClass (RBD, replicated) used by Prometheus, Alertmanager, Volsync, and anything else that needs persistent storage.

---

## Operator

### CSI

| Value                          | Setting              | Effect                                                                 |
| ------------------------------ | -------------------- | ---------------------------------------------------------------------- |
| `csi.enableCephfsDriver`       | `false`              | CephFS disabled — RBD only                                             |
| `csi.enableCephfsSnapshotter`  | `false`              | No CephFS snapshot support needed                                      |
| `csi.enableLiveness`           | `true`               | CSI liveness metrics exposed for Prometheus                            |
| `csi.cephFSKernelMountOptions` | `ms_mode=prefer-crc` | CephFS mount option (no-op since CephFS disabled, but kept for safety) |
| `csi.serviceMonitor.enabled`   | `true`               | Prometheus scrapes CSI sidecars                                        |

Resource limits are set conservatively for each CSI sidecar (`csi-provisioner`, `csi-resizer`, `csi-attacher`, `csi-snapshotter`, `csi-rbdplugin`, `liveness-prometheus`). These are tighter than upstream defaults to reduce footprint.

### Operator resources

```
requests: 128Mi memory, 100Mi CPU
limits: none
```

Memory request is fixed by upstream — marked `# unchangable` in values.

`cephCommandsTimeoutSeconds: "20"` — Ceph CLI commands invoked by the operator time out at 20s instead of the default 15s. Slightly more tolerant of slow Ceph responses.

---

## Cluster

### Storage

| Value                          | Setting   | Effect                                |
| ------------------------------ | --------- | ------------------------------------- |
| `storage.useAllNodes`          | `true`    | OSD pods scheduled on every node      |
| `storage.useAllDevices`        | `false`   | Don't auto-discover all block devices |
| `storage.deviceFilter`         | `nvme0n1` | Only use `nvme0n1` on each node       |
| `storage.config.osdsPerDevice` | `"1"`     | One OSD per NVMe                      |

All cluster storage is on NVMe. Using `deviceFilter` rather than `useAllDevices` to avoid accidentally using other devices.

### Network

| Value                              | Setting | Effect                                                             |
| ---------------------------------- | ------- | ------------------------------------------------------------------ |
| `network.provider`                 | `host`  | Ceph uses host networking — no pod overlay for storage traffic     |
| `network.connections.requireMsgr2` | `true`  | Enforces Ceph msgr2 protocol (encryption + authentication capable) |

Host networking means Ceph replication and client traffic bypasses the CNI entirely, using direct node IPs.

### Replication

`ceph-blockpool` uses `failureDomain: host`, `replicated.size: 2`. Data is replicated across 2 nodes. With 2 replicas, losing 1 node keeps the pool available but leaves no further redundancy.

> If you're down to 1 node, the pool will be degraded but still accessible until the second copy is restored.

### Ceph config

| Setting                          | Value   | Effect                                                                       |
| -------------------------------- | ------- | ---------------------------------------------------------------------------- |
| `bdev_enable_discard`            | `true`  | Enables TRIM/discard on OSDs — reclaims space on thin-provisioned NVMe       |
| `bdev_async_discard_threads`     | `1`     | One thread for async discard processing                                      |
| `osd_class_update_on_start`      | `false` | Don't reclassify OSD device class on restart (prevents unexpected rebalance) |
| `device_failure_prediction_mode` | `local` | Uses local ML model for disk failure prediction                              |
| `mon.mon_data_avail_warn`        | `"20"`  | Warn when mon disk is <20% free (default is 30%)                             |

### MGR modules

| Module                 | Effect                                                                 |
| ---------------------- | ---------------------------------------------------------------------- |
| `diskprediction_local` | Local disk failure prediction (feeds `device_failure_prediction_mode`) |
| `insights`             | Collects health metrics for the dashboard                              |
| `pg_autoscaler`        | Automatically adjusts PG counts per pool based on usage                |
| `rook`                 | Rook-specific mgr module for operator integration                      |

### CSI read affinity

```yaml
csi:
  readAffinity:
    enabled: true
    crushLocationLabels: ["kubernetes.io/hostname"]
```

RBD reads are served from the OSD on the same node as the pod when possible. Reduces cross-node traffic for read-heavy workloads.

### Dashboard

Accessible at `rook.chkpwd.com` via the private gateway. `ssl: false` because TLS is terminated at the gateway. Prometheus endpoint set to `http://prometheus-operated.monitoring.svc.cluster.local:9090` so the dashboard can show performance graphs.

### Cleanup policy

`wipeDevicesFromOtherClusters: true` — if the NVMe has Ceph data from a previous cluster install, it'll be wiped. Useful during reinstalls without manually dd'ing the drives.

---

## StorageClass: `ceph-block`

| Setting                | Value                                                       |
| ---------------------- | ----------------------------------------------------------- |
| `reclaimPolicy`        | `Delete`                                                    |
| `allowVolumeExpansion` | `true`                                                      |
| `volumeBindingMode`    | `Immediate`                                                 |
| `mountOptions`         | `["discard"]`                                               |
| `imageFeatures`        | `layering,fast-diff,object-map,deep-flatten,exclusive-lock` |
| `fstype`               | `ext4`                                                      |

`discard` mount option passes TRIM commands through to the OSD, which in turn uses `bdev_enable_discard`. `fast-diff` + `object-map` enable efficient diff tracking (used by `deep-flatten` and snapshot operations, including Volsync).

---

## Troubleshooting

```bash
# Cluster health
kubectl -n rook-ceph exec deploy/rook-ceph-tools -- ceph status
kubectl -n rook-ceph exec deploy/rook-ceph-tools -- ceph osd status

# Check OSD usage
kubectl -n rook-ceph exec deploy/rook-ceph-tools -- ceph df

# Check PG status
kubectl -n rook-ceph exec deploy/rook-ceph-tools -- ceph pg stat

# List OSDs and their devices
kubectl -n rook-ceph exec deploy/rook-ceph-tools -- ceph osd tree

# Check operator logs
kubectl -n rook-ceph logs deploy/rook-ceph-operator
```

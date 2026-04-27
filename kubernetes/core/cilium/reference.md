# Cilium Reference

Helm chart **v1.19.2**.

---

## What it does

Cilium replaces kube-proxy entirely (`kubeProxyReplacement: true`) and handles all pod networking via eBPF. It advertises LoadBalancer IPs to MikroTik via BGP and allocates IPs from the `10.0.45.0/24` pool via `CiliumLoadBalancerIPPool`.

Gateway API ingress is handled by **envoy-gateway** (see `kubernetes/core/envoy-gateway/`). Cilium's built-in Gateway API controller and embedded Envoy are both disabled.

---

## Key values

### Routing

| Value                    | Setting         | Effect                                                                                    |
| ------------------------ | --------------- | ----------------------------------------------------------------------------------------- |
| `routingMode`            | `native`        | Pods route directly without encapsulation (VXLAN/Geneve off)                              |
| `autoDirectNodeRoutes`   | `true`          | Adds host routes for pod CIDRs on each node automatically                                 |
| `ipv4NativeRoutingCIDR`  | `10.244.0.0/16` | The pod CIDR — tells Cilium not to masquerade traffic within this range                   |
| `ipam.mode`              | `kubernetes`    | Cilium defers IP allocation to the Kubernetes node IPAM                                   |
| `endpointRoutes.enabled` | `true`          | Per-endpoint routes instead of per-node — more precise, needed for native routing         |
| `enableIPv4BIGTCP`       | `true`          | Enables BIG TCP for IPv4 — allows GSO/GRO packets larger than 64KiB for better throughput |
| `pmtuDiscovery.enabled`  | `true`          | Path MTU discovery — avoids fragmentation on routes with smaller MTU                      |

### kube-proxy replacement

| Value                                 | Setting         | Effect                                                                                      |
| ------------------------------------- | --------------- | ------------------------------------------------------------------------------------------- |
| `kubeProxyReplacement`                | `true`          | Cilium handles all Service/ClusterIP traffic via eBPF, kube-proxy not needed                |
| `k8sServiceHost`                      | `127.0.0.1`     | API server address Cilium uses internally (local haproxy/LB)                                |
| `k8sServicePort`                      | `7445`          | Port for the above                                                                          |
| `kubeProxyReplacementHealthzBindAddr` | `0.0.0.0:10256` | Health endpoint on the same port kube-proxy would use — keeps node readiness checks working |

### Load balancing

| Value                           | Setting       | Effect                                                                          |
| ------------------------------- | ------------- | ------------------------------------------------------------------------------- |
| `loadBalancer.algorithm`        | `maglev`      | Consistent hashing for backend selection — same client always hits same pod     |
| `loadBalancer.mode`             | `dsr`         | Direct Server Return mode for load balancer traffic                             |
| `loadBalancer.acceleration`     | `best-effort` | Use XDP acceleration for LB when available, fall back gracefully                |
| `loadBalancer.dsrDispatch`      | `opt`         | DSR dispatch via IP options (used when DSR mode is active on specific services) |
| `localRedirectPolicies.enabled` | `true`        | Enables local redirect policies for steering traffic to node-local backends     |
| `socketLB.enabled`              | `true`        | Socket-level load balancing — intercepts at connect() for lower latency         |
| `socketLB.hostNamespaceOnly`    | `true`        | Socket LB only in host namespace — avoids interference with pod networking      |

### BGP

| Value                     | Setting | Effect                                                                                |
| ------------------------- | ------- | ------------------------------------------------------------------------------------- |
| `bgpControlPlane.enabled` | `true`  | Enables Cilium's BGP control plane (new API, replaces legacy `bgp.enabled`)           |
| `l2announcements.enabled` | `false` | L2 announcements disabled — BGP is used exclusively for LoadBalancer IP advertisement |

BGP sessions are configured via `bgp.yml` (`CiliumBGPClusterConfig` + `CiliumBGPPeerConfig` + `CiliumBGPAdvertisement`):

- **Cilium ASN**: `64513` (all k8s nodes)
- **MikroTik ASN**: `64512` (peer: `10.0.10.1`)
- **Advertised IPs**: all `LoadBalancer` service IPs (from the `10.0.45.0/24` pool)

MikroTik peer connections are managed in `terraform/mikrotik/bgp.tf`.

> The `CiliumLoadBalancerIPPool` in `pools.yml` allocates `10.0.45.0/24` for LoadBalancer Services.

### Gateway API (disabled)

| Value                | Setting | Effect                                               |
| -------------------- | ------- | ---------------------------------------------------- |
| `gatewayAPI.enabled` | `false` | Cilium's built-in Gateway API controller is disabled |
| `envoy.enabled`      | `false` | Cilium's embedded Envoy proxy is disabled            |

Gateway API is now managed by envoy-gateway running in the `networking` namespace. See `kubernetes/core/envoy-gateway/reference.md` for details. Cilium still provides the LoadBalancer IP allocation (via `CiliumLoadBalancerIPPool`) and BGP advertisement for the envoy-gateway Services.

### BPF / eBPF

| Value                  | Setting  | Effect                                                                     |
| ---------------------- | -------- | -------------------------------------------------------------------------- |
| `bpf.datapathMode`     | `netkit` | Uses netkit device mode — newer, faster alternative to veth pairs          |
| `bpf.masquerade`       | `true`   | eBPF-based masquerade instead of iptables for SNAT                         |
| `bpf.preallocateMaps`  | `true`   | Pre-allocates BPF map memory at startup — avoids runtime allocation stalls |
| `bpf.lbModeAnnotation` | `true`   | Allows per-service LB mode override via annotation                         |

### cgroup

| Value                      | Setting          | Effect                                                             |
| -------------------------- | ---------------- | ------------------------------------------------------------------ |
| `cgroup.autoMount.enabled` | `false`          | Cilium does not mount cgroupv2 — already mounted by the OS (Talos) |
| `cgroup.hostRoot`          | `/sys/fs/cgroup` | Path to the host cgroup filesystem                                 |

### Observability

| Value                                            | Setting      | Effect                                                      |
| ------------------------------------------------ | ------------ | ----------------------------------------------------------- |
| `dashboards.enabled`                             | `true`       | Deploy Grafana dashboard ConfigMaps for Cilium metrics      |
| `dashboards.annotations.grafana_folder`          | `Kubernetes` | Place dashboards in the "Kubernetes" folder in Grafana      |
| `operator.dashboards.enabled`                    | `true`       | Deploy Grafana dashboard ConfigMaps for the Cilium operator |
| `operator.dashboards.annotations.grafana_folder` | `Kubernetes` | Same folder for operator dashboards                         |

### Misc

| Value                  | Setting | Effect                                                          |
| ---------------------- | ------- | --------------------------------------------------------------- |
| `cni.exclusive`        | `false` | Allow other CNI plugins alongside Cilium (needed for Multus)    |
| `hubble.enabled`       | `false` | Hubble observability plane disabled                             |
| `operator.rollOutPods` | `true`  | Operator pods restart automatically on ConfigMap/Secret changes |
| `rollOutCiliumPods`    | `true`  | Agent pods restart automatically on config changes              |

---

## Security capabilities

The `securityContext.capabilities` block is required for the eBPF agent to function — `NET_ADMIN`, `SYS_ADMIN`, `NET_RAW` etc. are all needed for loading BPF programs and managing network interfaces. `cleanCiliumState` runs on uninstall/restart to tear down BPF maps.

---

## Troubleshooting

```bash
# Check Cilium agent status on a node
kubectl -n kube-system exec ds/cilium -- cilium status

# Check BGP peer session state
kubectl -n kube-system exec ds/cilium -- cilium bgp peers

# Check BGP route advertisements
kubectl -n kube-system exec ds/cilium -- cilium bgp routes

# Check LoadBalancer IP pool usage
kubectl get ciliumloadbalancerippools

# Verify kube-proxy replacement
kubectl -n kube-system exec ds/cilium -- cilium status | grep KubeProxy

# On MikroTik: verify BGP sessions and installed routes
# /routing bgp session print
# /ip route print where bgp
```

# Cilium Reference

Helm chart **v1.19.1**.

---

## What it does

Cilium replaces kube-proxy entirely (`kubeProxyReplacement: true`) and handles all pod networking via eBPF. It also runs the GatewayAPI controller that creates the `private` and `public` Gateways, and advertises LoadBalancer IPs to MikroTik via BGP.

---

## Key values

### Routing

| Value                    | Setting         | Effect                                                                            |
| ------------------------ | --------------- | --------------------------------------------------------------------------------- |
| `routingMode`            | `native`        | Pods route directly without encapsulation (VXLAN/Geneve off)                      |
| `autoDirectNodeRoutes`   | `true`          | Adds host routes for pod CIDRs on each node automatically                         |
| `ipv4NativeRoutingCIDR`  | `10.244.0.0/16` | The pod CIDR — tells Cilium not to masquerade traffic within this range           |
| `ipam.mode`              | `kubernetes`    | Cilium defers IP allocation to the Kubernetes node IPAM                           |
| `endpointRoutes.enabled` | `true`          | Per-endpoint routes instead of per-node — more precise, needed for native routing |

### kube-proxy replacement

| Value                                 | Setting         | Effect                                                                                      |
| ------------------------------------- | --------------- | ------------------------------------------------------------------------------------------- |
| `kubeProxyReplacement`                | `true`          | Cilium handles all Service/ClusterIP traffic via eBPF, kube-proxy not needed                |
| `k8sServiceHost`                      | `127.0.0.1`     | API server address Cilium uses internally (local haproxy/LB)                                |
| `k8sServicePort`                      | `7445`          | Port for the above                                                                          |
| `kubeProxyReplacementHealthzBindAddr` | `0.0.0.0:10256` | Health endpoint on the same port kube-proxy would use — keeps node readiness checks working |

### Load balancing

| Value                    | Setting  | Effect                                                                      |
| ------------------------ | -------- | --------------------------------------------------------------------------- |
| `loadBalancer.algorithm` | `maglev` | Consistent hashing for backend selection — same client always hits same pod |
| `loadBalancer.mode`      | `dsr`    | Direct Server Return: reply traffic bypasses the load balancer node         |
| `localRedirectPolicy`    | `true`   | Redirects traffic to local node backends first when available               |

### BGP

| Value                     | Setting | Effect                                                                                |
| ------------------------- | ------- | ------------------------------------------------------------------------------------- |
| `bgpControlPlane.enabled` | `true`  | Enables Cilium's BGP control plane (new API, replaces legacy `bgp.enabled`)           |
| `l2announcements.enabled` | `false` | L2 announcements disabled — BGP is used exclusively for LoadBalancer IP advertisement |

BGP sessions are configured via `bgp.yml` (`CiliumBGPClusterConfig` + `CiliumBGPPeerConfig` + `CiliumBGPAdvertisement`):

- **Cilium ASN**: `64513` (all k8s nodes)
- **MikroTik ASN**: `64512` (peer: `10.0.10.1`)
- **Advertised IPs**: all `LoadBalancer` service IPs (from the `10.0.10.0/24` pool)

MikroTik peer connections are managed in `terraform/mikrotik/bgp.tf`.

> The `CiliumLoadBalancerIPPool` in `pools.yml` allocates `10.0.10.0/24` for LoadBalancer Services.

### Gateway API

| Value                                | Setting       | Effect                                                                                |
| ------------------------------------ | ------------- | ------------------------------------------------------------------------------------- |
| `gatewayAPI.enabled`                 | `true`        | Cilium creates the GatewayClass `cilium` and manages Gateway/HTTPRoute reconciliation |
| `gatewayAPI.gatewayClass.create`     | `"true"`      | Auto-creates the `cilium` GatewayClass resource                                       |
| `gatewayAPI.secretsNamespace.name`   | `kube-system` | Where Cilium looks for TLS secrets referenced by Gateways                             |
| `gatewayAPI.secretsNamespace.create` | `false`       | Namespace already exists, don't recreate                                              |

### BPF / eBPF

| Value            | Setting | Effect                                             |
| ---------------- | ------- | -------------------------------------------------- |
| `bpf.masquerade` | `true`  | eBPF-based masquerade instead of iptables for SNAT |

### Misc

| Value                  | Setting | Effect                                                          |
| ---------------------- | ------- | --------------------------------------------------------------- |
| `cni.exclusive`        | `false` | Allow other CNI plugins alongside Cilium (needed for Multus)    |
| `hubble.enabled`       | `false` | Hubble observability plane disabled                             |
| `envoy.enabled`        | `false` | Embedded Envoy proxy disabled — L7 policy not in use            |
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

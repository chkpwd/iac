# Cilium BGP Migration Guide

## What is BGP?

BGP (Border Gateway Protocol) is the routing protocol that holds the internet together. Every major ISP, cloud provider, and enterprise network uses it to exchange information about which IP address blocks live where.

In plain terms: BGP lets routers tell each other "I can reach these IP prefixes — send traffic my way".

### Key vocabulary

| Term                                              | What it means                                                                                                                                                                                                                                                                                                                                            |
| ------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **AS (Autonomous System)**                        | An independently operated network with a single routing policy. Your homelab is one AS, your MikroTik router is the gateway for it.                                                                                                                                                                                                                      |
| **ASN (Autonomous System Number)**                | The unique number that identifies an AS. Think of it like an IP address but for entire networks. Publicly registered ASNs require an RIR allocation; **private ASNs (64512–65535) are free to use internally**, the same way RFC 1918 addresses are free to use privately. You just need the two sides of a peering session to have _different_ numbers. |
| **eBGP (External BGP)**                           | A BGP session between two _different_ ASes. This is what you are configuring: MikroTik (AS 64512) peering with Kubernetes nodes (AS 64513).                                                                                                                                                                                                              |
| **iBGP (Internal BGP)**                           | BGP sessions within the same AS. Not used here.                                                                                                                                                                                                                                                                                                          |
| **Peer / Neighbor**                               | A router you have established a BGP session with.                                                                                                                                                                                                                                                                                                        |
| **Prefix / Route advertisement**                  | A BGP peer saying "I own this CIDR block, route packets there through me".                                                                                                                                                                                                                                                                               |
| **NLRI (Network Layer Reachability Information)** | The actual list of IP prefixes exchanged in a BGP UPDATE message.                                                                                                                                                                                                                                                                                        |

### Why two ASNs for a homelab?

eBGP (between _different_ AS numbers) is simpler and more common for this use-case because:

- eBGP peers do not need an IGP (OSPF, etc.) to resolve next-hops
- Loop prevention is built-in via AS-PATH: if a prefix comes back to the AS that originated it, it is dropped
- Cilium's BGP control plane is designed around eBGP peering with an upstream router

---

## Why switch from L2 announcements to BGP?

The previous setup used `l2announcements.enabled: true` — Cilium responded to ARP requests for LoadBalancer IPs (similar to Gratuitous ARP / MetalLB in L2 mode). This works but has trade-offs:

|                       | L2 Announcements                                         | BGP                                                           |
| --------------------- | -------------------------------------------------------- | ------------------------------------------------------------- |
| **How it works**      | One node owns each VIP and answers ARP                   | Router learns the VIP as a routed prefix                      |
| **Failover speed**    | Slow — dependent on ARP cache aging (seconds to minutes) | Fast — BGP withdrawal is near-instant                         |
| **Load distribution** | One node takes all traffic for a VIP                     | ECMP possible across all nodes advertising the prefix         |
| **Network scope**     | Same L2 broadcast domain only                            | Works across routed networks / VLANs                          |
| **Requires**          | Nothing upstream                                         | BGP-capable upstream router (MikroTik supports this natively) |

---

## Architecture after migration

```
┌─────────────────────────────────────────────────────────┐
│  MikroTik                                                │
│  ASN: 64512   IP: 10.0.10.1                             │
│                                                          │
│  BGP peers:  10.0.10.10, .11, .12 (k8s nodes)          │
└────────────────────────┬────────────────────────────────┘
                         │ eBGP sessions (TCP 179)
          ┌──────────────┼──────────────┐
          ▼              ▼              ▼
   ct-k8s-01       ct-k8s-02      ct-k8s-03
   10.0.10.10      10.0.10.11     10.0.10.12
   ASN: 64513      ASN: 64513     ASN: 64513
          │              │              │
          └──────────────┴──────────────┘
                Cilium BGP Control Plane
          advertises LoadBalancer IPs from:
               CiliumLoadBalancerIPPool
                    10.0.10.0/24
```

Cilium runs a BGP speaker on each node. When a `LoadBalancer` Service gets an IP from the pool, Cilium advertises that prefix to MikroTik over eBGP. MikroTik installs a route for it and traffic flows directly to the advertising node(s).

---

## What changed

### `values.yml`

| Key                       | Before  | After   | Why                                       |
| ------------------------- | ------- | ------- | ----------------------------------------- |
| `bgp.enabled`             | `false` | removed | Legacy key, replaced by `bgpControlPlane` |
| `bgpControlPlane.enabled` | absent  | `true`  | Enables the new BGP control plane         |
| `l2announcements.enabled` | `true`  | `false` | Replaced by BGP                           |

### New file: `bgp.yml`

Three new CRD objects:

1. **`CiliumBGPClusterConfig`** — declares local ASN `64513` for all Linux nodes and references the peer config
2. **`CiliumBGPPeerConfig`** — tuning knobs for the MikroTik peer (timers, address families)
3. **`CiliumBGPAdvertisement`** — tells Cilium to advertise `LoadBalancerIP` addresses for all services

### New file: `terraform/mikrotik/bgp.tf`

Creates one `routeros_routing_bgp_connection` per k8s node (ct-k8s-01/02/03) with:

- MikroTik local ASN `64512`, local address `10.0.10.1`
- Remote ASN `64513`, remote addresses `10.0.10.10-12`

### `kustomization.yml`

- Added `bgp.yml` to `resources`
- `policy.yml` (L2 announcement policy) commented out

---

## Migration steps (in order)

1. **Apply MikroTik Terraform**

   ```bash
   cd terraform/mikrotik
   terraform plan
   terraform apply
   ```

   This creates the BGP peer entries on MikroTik pointing at each k8s node. Sessions will be in `Idle/Active` until Cilium is configured.

2. **Commit and push the Cilium changes**
   Flux will pick up `values.yml` and `bgp.yml`. The Cilium rollout:
   - Restarts all Cilium pods with `bgpControlPlane.enabled: true`
   - Applies the `CiliumBGPClusterConfig` and related CRDs
   - Starts BGP sessions toward `10.0.10.1` (MikroTik)

3. **Verify BGP sessions**

   ```bash
   kubectl -n kube-system exec ds/cilium -- cilium bgp peers
   ```

   Expected: all 3 nodes show `established` toward `10.0.10.1`.

4. **Verify route advertisements**

   ```bash
   kubectl -n kube-system exec ds/cilium -- cilium bgp routes
   ```

   You should see the LoadBalancer IPs from the `10.0.10.0/24` pool.

5. **Verify on MikroTik**

   ```
   /routing bgp session print
   /ip route print where bgp
   ```

   Routes for LoadBalancer IPs should appear with next-hops pointing at the k8s nodes.

6. **Test connectivity**
   Hit a LoadBalancer service IP from a device on the LAN. Traffic should route through MikroTik to a k8s node without going through ARP.

---

## Verification commands

```bash
# Cilium BGP status
kubectl -n kube-system exec ds/cilium -- cilium bgp peers
kubectl -n kube-system exec ds/cilium -- cilium bgp routes

# All LoadBalancer service IPs
kubectl get svc -A --field-selector spec.type=LoadBalancer

# Pool status
kubectl get ciliumloadbalancerippools

# Cilium overall health
kubectl -n kube-system exec ds/cilium -- cilium status
```

---

## Troubleshooting

| Symptom                                     | Likely cause                          | Fix                                                                                                                             |
| ------------------------------------------- | ------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| BGP session stays `Idle`                    | TCP 179 blocked by firewall           | Add firewall accept rule for port 179 between `10.0.10.0/24` and router                                                         |
| Session `Active` but never `Established`    | ASN mismatch or wrong peer IP         | Verify MikroTik peer has `remote.as = 64513` and correct node IPs                                                               |
| Session establishes but no routes           | `CiliumBGPAdvertisement` not matching | Check label `advertise: bgp` propagation on `CiliumBGPPeerConfig`                                                               |
| Routes installed but traffic fails          | DSR interaction                       | Check `loadBalancer.mode: dsr` is still functional — DSR requires that the node receiving the packet is also the one responding |
| MikroTik shows routes but LB IP unreachable | No firewall forward rule              | Ensure MikroTik forwards traffic for `10.0.10.0/24` on the LAN bridge                                                           |

---

## BGP testing tools

Before Cilium is configured, you can validate that MikroTik is listening and will complete the BGP handshake using a software BGP speaker. Here is a summary of the available tools and what each is useful for.

| Tool             | Language | Install                                                                 | What it does                                                                                                                 | Best for                                                                                 |
| ---------------- | -------- | ----------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| **exabgp**       | Python   | `pip install exabgp`                                                    | Full BGP speaker — opens a real session, exchanges OPEN/KEEPALIVE/UPDATE messages, can advertise/withdraw prefixes on demand | Testing, scripting, injecting routes into a network. Used below.                         |
| **gobgp**        | Go       | Not in Homebrew; `go install github.com/osrg/gobgp/v3/cmd/gobgp@latest` | Full BGP daemon + CLI (`gobgp bgp neighbor`), gRPC API                                                                       | Production-grade daemon or interactive testing on Linux                                  |
| **birdc**        | C        | `apt install bird2`                                                     | CLI for the BIRD routing daemon                                                                                              | Production routing stack on Linux, route reflection                                      |
| **vtysh**        | C        | Comes with FRRouting (FRR)                                              | Shell-like CLI for the full FRR routing suite (BGP, OSPF, IS-IS, etc.)                                                       | Full routing stack, overkill for a simple test                                           |
| **bgpdump**      | C        | `brew install bgpdump`                                                  | Parses MRT/RIB dump files                                                                                                    | Offline analysis of BGP table snapshots, not live sessions                               |
| **nc + tcpdump** | —        | Pre-installed                                                           | `nc 10.0.10.1 179` opens a raw TCP connection; `tcpdump port 179` captures raw BGP packets                                   | Packet-level inspection without a real speaker; not sufficient to complete a BGP session |

### Why exabgp?

exabgp speaks real BGP but is driven entirely by config files and stdin/stdout — no routing daemon overhead, no kernel route changes. It was designed specifically for scripting and testing BGP peers, and its verbose output decodes every message in human-readable form.

---

## Pre-Cilium BGP session test (completed)

This test was run **after `terraform apply`** (MikroTik has peer entries for `10.0.10.10-12`) but **before Cilium's BGP control plane** was enabled — to confirm the MikroTik side is correct independently.

### Setup

A temporary `netshoot` pod was launched on `ct-k8s-01` (`10.0.10.10`) using host networking, so it shares the node's IP which MikroTik already expects as a peer:

```bash
kubectl run bgp-test \
  --image=nicolaka/netshoot \
  --restart=Never \
  --overrides='{"spec":{"nodeSelector":{"kubernetes.io/hostname":"ct-k8s-01"},"hostNetwork":true}}' \
  -- sleep 600
```

exabgp was installed inside the pod and the following minimal config was used:

```
neighbor 10.0.10.1 {
  description   "MikroTik BGP test";
  router-id     10.0.10.10;
  local-as      64513;
  peer-as       64512;
  local-address 10.0.10.10;
}
```

### What happened (annotated output)

```
outgoing-1  attempting connection to 10.0.10.1:179
```

TCP connection to MikroTik on port 179 succeeded.

```
outgoing-1  >> OPEN version=4 asn=64513 hold_time=180 router_id=10.0.10.10
```

exabgp sent its BGP OPEN message: "I am AS 64513, my router-id is 10.0.10.10".

```
outgoing-1  << OPEN version=4 asn=64512 hold_time=180 router_id=10.6.6.1
            capabilities=[Multiprotocol(ipv4 unicast), Route Refresh, Graceful Restart, ASN4(64512)]
```

MikroTik responded with its own OPEN: AS 64512 confirmed, router-id is its Wireguard interface IP (`10.6.6.1`). The ASN negotiation is correct. MikroTik advertised only `ipv4 unicast` capability — which is exactly what Cilium will use.

```
outgoing-1  >> KEEPALIVE (OPENCONFIRM)
outgoing-1  << KEEPALIVE
```

Both sides exchanged KEEPALIVE — this is the final step of the BGP handshake. **The session reached `Established` state.**

The capability mismatch warnings (IPv6, L2VPN, BGP-LS, etc.) are informational — exabgp offered many families that MikroTik doesn't support. They are negotiated out automatically and do not affect the session. Cilium will only offer `ipv4 unicast`, so none of these warnings will appear in production.

### Conclusion

MikroTik accepted the connection, matched AS 64512 vs 64513 correctly, and the session established cleanly. The Terraform peer configuration is valid. Cilium can now be deployed.

```bash
# Cleanup
kubectl delete pod bgp-test
```

# Envoy Gateway Reference

Helm chart **v1.7.1** from `oci://mirror.gcr.io/envoyproxy/gateway-helm`.

---

## What it does

Envoy Gateway is a Kubernetes-native Gateway API implementation built on Envoy Proxy. It replaces Cilium's built-in Gateway API controller and embedded Envoy, providing a dedicated, feature-rich ingress data plane with fine-grained traffic policies.

The controller runs in the `networking` namespace. When a Gateway resource is created, envoy-gateway spawns Envoy proxy pods in the same namespace (`GatewayNamespace` deploy type), creating predictable Service names.

---

## Architecture

```
                       ┌─────────────────────────┐
                       │    envoy-gateway         │
                       │    (controller)          │
                       │    networking namespace  │
                       └────────┬────────────────┘
                                │ watches Gateway/HTTPRoute/policy CRDs
                    ┌───────────┴───────────┐
                    ▼                       ▼
           ┌──────────────┐       ┌──────────────┐
           │ Envoy Proxy  │       │ Envoy Proxy  │
           │ (private gw) │       │ (public gw)  │
           │ 10.0.45.30   │       │ 10.0.45.31   │
           └──────────────┘       └──────────────┘
                    │                       │
                    └───────────┬───────────┘
                                │ LoadBalancer IPs from
                                │ CiliumLoadBalancerIPPool
                                │ advertised via BGP
                                ▼
                        ┌──────────────┐
                        │   MikroTik   │
                        │  (upstream)  │
                        └──────────────┘
```

---

## Helm values

| Value                                                      | Setting            | Effect                                                                               |
| ---------------------------------------------------------- | ------------------ | ------------------------------------------------------------------------------------ |
| `config.envoyGateway.extensionApis.enableBackend`          | `true`             | Enables the Backend extension API for routing to non-Service backends                |
| `config.envoyGateway.extensionApis.enableEnvoyPatchPolicy` | `true`             | Enables EnvoyPatchPolicy for low-level Envoy config patches (e.g. Zstd compression)  |
| `config.envoyGateway.provider.type`                        | `Kubernetes`       | Standard Kubernetes provider                                                         |
| `config.envoyGateway.provider.kubernetes.deploy.type`      | `GatewayNamespace` | Envoy proxy pods deploy in the Gateway's namespace, giving predictable Service names |

---

## GatewayClass

A single `GatewayClass` named `envoy-gateway` is created with:

- **Controller**: `gateway.envoyproxy.io/gatewayclass-controller`
- **Parameters**: references the `EnvoyProxy` resource `envoy-proxy-config` in `networking`

Both the `private` and `public` Gateways (defined in `kubernetes/core/gateway-api/`) use this GatewayClass.

---

## EnvoyProxy resource

The `envoy-proxy-config` EnvoyProxy resource configures the Envoy data plane pods spawned for each Gateway:

| Setting                              | Value                      | Effect                                                               |
| ------------------------------------ | -------------------------- | -------------------------------------------------------------------- |
| `logging.level.default`              | `info`                     | Default log level for all Envoy components                           |
| `envoyDaemonSet.container.resources` | 50m/128Mi req, 1/512Mi lim | Resource bounds for each Envoy proxy pod                             |
| `envoyService.externalTrafficPolicy` | `Local`                    | Preserves client source IPs — traffic only routed to local node pods |
| `shutdown.drainTimeout`              | `180s`                     | Envoy drains connections for 3 minutes before shutting down          |
| `telemetry.metrics.prometheus`       | Gzip compressed            | Prometheus metrics endpoint with gzip compression                    |

---

## ClientTrafficPolicy

Two policies, one per gateway, configured in `client-traffic-policy.yml`. These control how Envoy handles inbound client connections.

### Shared settings (both gateways)

| Setting                              | Value                                | Effect                                                       |
| ------------------------------------ | ------------------------------------ | ------------------------------------------------------------ |
| `clientIPDetection`                  | trustedCIDRs `10.244.0.0/16`         | Trust XFF headers from pod CIDR for real client IP detection |
| `http2.onInvalidMessage`             | `TerminateStream`                    | Immediately terminate malformed HTTP/2 streams               |
| `tls.minVersion`                     | `1.2`                                | Minimum TLS 1.2                                              |
| `tls.maxVersion`                     | `1.3`                                | Maximum TLS 1.3                                              |
| `tls.ciphers`                        | ECDHE-ECDSA-AES128/256-GCM, CHACHA20 | Strong AEAD-only cipher suites                               |
| `tls.ecdhCurves`                     | X25519, P-256                        | Modern key exchange curves                                   |
| `tls.signatureAlgorithms`            | ECDSA P-256/384/521, Ed25519         | ECDSA and EdDSA signatures only (no RSA)                     |
| `headers.enableEnvoyHeaders`         | `false`                              | Don't add `x-envoy-*` headers to responses                   |
| `headers.lateResponseHeaders.remove` | Server, X-Powered-By, X-AspNet-\*    | Strip server identity headers                                |
| `headers.lateResponseHeaders.set`    | HSTS preload                         | Always set Strict-Transport-Security                         |

### Private gateway differences

| Setting                               | Value   | Rationale                                                                        |
| ------------------------------------- | ------- | -------------------------------------------------------------------------------- |
| `connection.bufferLimit`              | `8Mi`   | Large buffer for internal apps (file uploads, Plex streams)                      |
| `timeout.http.requestReceivedTimeout` | `3600s` | 1-hour timeout — allows long-running internal connections (WebSocket, streaming) |
| `tcpKeepalive`                        | `{}`    | Default keepalive (OS defaults)                                                  |

### Public gateway differences

| Setting                               | Value     | Rationale                                                        |
| ------------------------------------- | --------- | ---------------------------------------------------------------- |
| `connection.bufferLimit`              | `100Ki`   | Small buffer — limits memory per connection from the internet    |
| `connection.socketBufferLimit`        | `1Mi`     | Kernel socket buffer cap                                         |
| `timeout.http.requestReceivedTimeout` | `10s`     | Aggressive timeout — drop slow/idle internet connections quickly |
| `tcpKeepalive.interval`               | `10s`     | Frequent keepalive probes to detect dead connections             |
| `tcpKeepalive.idleTime`               | `10s`     | Start probing after 10s idle                                     |
| Additional security headers           | See below | Full hardening headers for internet-facing traffic               |

**Public-only security headers** (set via `lateResponseHeaders`):

| Header                         | Value                |
| ------------------------------ | -------------------- |
| `X-Robots-Tag`                 | `noindex, nofollow`  |
| `X-Frame-Options`              | `DENY`               |
| `X-Content-Type-Options`       | `nosniff`            |
| `X-XSS-Protection`             | `1; mode=block`      |
| `Referrer-Policy`              | `no-referrer`        |
| `X-DNS-Prefetch-Control`       | `off`                |
| `Permissions-Policy`           | `interest-cohort=()` |
| `Cross-Origin-Opener-Policy`   | `same-origin`        |
| `Cross-Origin-Resource-Policy` | `same-site`          |
| `Cross-Origin-Embedder-Policy` | `require-corp`       |

---

## BackendTrafficPolicy

Two policies, one per gateway, configured in `backend-traffic-policy.yml`. These control how Envoy communicates with upstream backends.

### Shared settings

| Setting        | Value              | Effect                                           |
| -------------- | ------------------ | ------------------------------------------------ |
| `compression`  | Brotli, Gzip, Zstd | Compress responses to clients (all three codecs) |
| `tcpKeepalive` | `{}`               | Default keepalive to backends                    |

### Private gateway

| Setting                       | Value | Rationale                                               |
| ----------------------------- | ----- | ------------------------------------------------------- |
| `connection.bufferLimit`      | `8Mi` | Matches client-side buffer for large internal transfers |
| `timeout.http.requestTimeout` | `0s`  | No timeout — internal requests can run indefinitely     |

### Public gateway

| Setting                       | Value   | Rationale                                           |
| ----------------------------- | ------- | --------------------------------------------------- |
| `connection.bufferLimit`      | `100Ki` | Tight buffer to limit backend memory per connection |
| `timeout.http.requestTimeout` | `10s`   | Hard 10s cap on backend response time               |
| `requestBuffer.limit`         | `100Ki` | Buffer request bodies up to 100Ki before forwarding |

---

## Flux dependency chain

```
gateway-api-crd (kube-system)       # CRDs installed first
        │
        ▼
envoy-gateway (networking)          # controller + GatewayClass + policies
        │
        ▼
gateway-api (networking)            # Gateways + certificate + redirect route
        │
        ▼
apps / core services                # HTTPRoutes referencing gateways
```

---

## Relationship with Cilium

Cilium's Gateway API controller (`gatewayAPI.enabled`) and embedded Envoy (`envoy.enabled`) are both **disabled**. Cilium still provides:

- **LoadBalancer IP allocation**: `CiliumLoadBalancerIPPool` assigns IPs from `10.0.45.0/24` to envoy-gateway's LoadBalancer Services via the `lbipam.cilium.io/ips` annotation on Gateway `infrastructure.annotations`
- **BGP advertisement**: Cilium's BGP control plane advertises the LoadBalancer IPs to the MikroTik router
- **CNI**: All pod networking, kube-proxy replacement, and eBPF data path

---

## File inventory

| File                         | Contents                                                                |
| ---------------------------- | ----------------------------------------------------------------------- |
| `source.yml`                 | OCIRepository for the envoy-gateway Helm chart                          |
| `helm-release.yml`           | HelmRelease with controller configuration values                        |
| `gateway-class.yml`          | GatewayClass `envoy-gateway` + EnvoyProxy `envoy-proxy-config`          |
| `client-traffic-policy.yml`  | ClientTrafficPolicy for `private` and `public` gateways                 |
| `backend-traffic-policy.yml` | BackendTrafficPolicy for `private` and `public` gateways                |
| `kustomization.yml`          | Kustomize resource list                                                 |
| `flux-kustomization.yml`     | Flux Kustomization targeting `networking`, depends on `gateway-api-crd` |

---

## Troubleshooting

```bash
# Check envoy-gateway controller
kubectl -n networking get pods -l app.kubernetes.io/name=envoy-gateway

# Check envoy proxy pods spawned for each gateway
kubectl -n networking get pods -l gateway.envoyproxy.io/owning-gateway-name

# Check GatewayClass status
kubectl get gatewayclass envoy-gateway

# Check gateway status and addresses
kubectl -n networking get gateways

# Check policy attachment status
kubectl -n networking get clienttrafficpolicies
kubectl -n networking get backendtrafficpolicies

# View envoy-gateway controller logs
kubectl -n networking logs -l app.kubernetes.io/name=envoy-gateway --tail=100

# View envoy proxy logs for a specific gateway
kubectl -n networking logs -l gateway.envoyproxy.io/owning-gateway-name=private --tail=100

# Dump resolved Envoy config (requires egctl)
# egctl config envoy-proxy -n networking -l gateway.envoyproxy.io/owning-gateway-name=private

# Verify TLS configuration
openssl s_client -connect gateway.chkpwd.com:443 -servername test.chkpwd.com </dev/null 2>/dev/null | openssl x509 -noout -text | grep -A2 "Protocol\|Cipher"

# Check that Cilium is still advertising the gateway LB IPs via BGP
kubectl -n kube-system exec ds/cilium -- cilium bgp routes
```

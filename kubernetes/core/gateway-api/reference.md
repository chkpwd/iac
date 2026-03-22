# Gateway API Reference

CRDs from `kubernetes-sigs/gateway-api` **v1.5.1** (experimental channel).
GatewayClass `envoy-gateway` provided by envoy-gateway (see `kubernetes/core/envoy-gateway/`).

---

## What it does

Provides the two cluster ingress gateways — `private` and `public` — both terminating TLS with a wildcard cert for `*.chkpwd.com`. All HTTP traffic is redirected to HTTPS via a shared HTTPRoute. Everything lives in the `networking` namespace.

---

## CRD install

The `gateway-api-crd` GitRepository pulls only `config/crd/experimental` from the upstream repo, which includes the experimental channel CRDs (HTTPRoute, Gateway, GatewayClass, plus newer alpha types). The `gateway-api` Kustomization depends on both `gateway-api-crd` and `envoy-gateway`, so CRDs and the controller are always installed first.

---

## Gateways

### `private` — `10.0.45.30`

Internal services. DNS target `gateway.chkpwd.com` (via `external-dns` annotation).

### `public` — `10.0.45.31`

Externally reachable services. DNS target `chkpwd.com`.

Both gateways:

- Bound to `envoy-gateway` GatewayClass (controller: `gateway.envoyproxy.io/gatewayclass-controller`)
- Listen on port 80 (HTTP, same-namespace routes only) and 443 (HTTPS, all namespaces)
- TLS terminated at the gateway using Secret `chkpwd-com-tls`
- LoadBalancer IPs assigned via `lbipam.cilium.io/ips` annotation and advertised over BGP by Cilium
- HTTP listener restricted to `Same` namespace (only the redirect route uses it)
- HTTPS listener accepts routes from `All` namespaces

---

## TLS Certificate

Managed by cert-manager (`ClusterIssuer: main-issuer`). Covers `chkpwd.com` and `*.chkpwd.com`, stored in Secret `chkpwd-com-tls`. Duration is **160h** (just under 7 days) — short rotation, relies on cert-manager's auto-renewal.

---

## HTTP -> HTTPS redirect

`http-redirect` HTTPRoute is attached to both gateways on the `http` section:

```yaml
filters:
  - type: RequestRedirect
    requestRedirect:
      scheme: https
      statusCode: 301
```

Permanent redirect — all plain HTTP to either gateway goes to HTTPS with no exceptions.

---

## Adding a new route

Any namespace can attach an HTTPRoute to either gateway:

```yaml
parentRefs:
  - name: private # or public
    namespace: networking
    sectionName: https
```

`sectionName: https` attaches to the TLS listener. Omitting it or using `http` will attach to the plaintext listener (which just redirects anyway).

---

## Troubleshooting

```bash
# Check gateway status / assigned IPs
kubectl -n networking get gateways

# Check route attachment
kubectl get httproutes -A

# Check cert
kubectl -n networking get certificate chkpwd-com
kubectl -n networking get secret chkpwd-com-tls

# Check envoy proxy pods spawned by gateways (GatewayNamespace deploy type)
kubectl -n networking get pods -l gateway.envoyproxy.io/owning-gateway-name

# Check GatewayClass status
kubectl get gatewayclass envoy-gateway -o yaml
```

# Gateway API Reference

CRDs from `kubernetes-sigs/gateway-api` **v1.5.1** (experimental channel).
GatewayClass `cilium` provided by Cilium.

---

## What it does

Provides the two cluster ingress gateways — `private` and `public` — both terminating TLS with a wildcard cert for `*.chkpwd.com`. All HTTP traffic is redirected to HTTPS via a shared HTTPRoute.

---

## CRD install

The `gateway-api-crd` GitRepository pulls only `config/crd/experimental` from the upstream repo, which includes the experimental channel CRDs (HTTPRoute, Gateway, GatewayClass, plus newer alpha types). The `gateway-api` Kustomization depends on `gateway-api-crd`, so CRDs are always installed first.

---

## Gateways

### `private` — `10.0.10.30`

Internal services. DNS target `gateway.chkpwd.com` (via `external-dns` annotation).

### `public` — `10.0.10.31`

Externally reachable services. DNS target `chkpwd.com`.

Both gateways:

- Bound to `cilium` GatewayClass
- Listen on port 80 (HTTP) and 443 (HTTPS) for `*.chkpwd.com`
- TLS terminated at the gateway using Secret `chkpwd-com-tls`
- Accept routes from all namespaces

---

## TLS Certificate

Managed by cert-manager (`ClusterIssuer: main-issuer`). Covers `chkpwd.com` and `*.chkpwd.com`, stored in Secret `chkpwd-com-tls`. Duration is 160h (just under 7 days) — short rotation, relies on cert-manager's auto-renewal.

---

## HTTP → HTTPS redirect

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
    namespace: kube-system
    sectionName: https
```

`sectionName: https` attaches to the TLS listener. Omitting it or using `http` will attach to the plaintext listener (which just redirects anyway).

---

## Troubleshooting

```bash
# Check gateway status / assigned IPs
kubectl -n kube-system get gateways

# Check route attachment
kubectl get httproutes -A

# Check cert
kubectl -n kube-system get certificate chkpwd-com
kubectl -n kube-system get secret chkpwd-com-tls
```

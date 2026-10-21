# Static per-node hostname (HostnameConfig doc, not machine.network.hostname).
---
apiVersion: v1alpha1
kind: HostnameConfig
auto: "off"
hostname: {{ .Node.Host }}

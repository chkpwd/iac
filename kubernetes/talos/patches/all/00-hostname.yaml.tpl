# Static hostname via HostnameConfig doc (not machine.network.hostname, which
# conflicts with the HostnameConfig doc topf emits).
---
apiVersion: v1alpha1
kind: HostnameConfig
auto: "off"
hostname: {{ .Node.Host }}

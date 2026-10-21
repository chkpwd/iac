# Static hostname per node. Must be the HostnameConfig *document* (not v1alpha1
# machine.network.hostname — setting it there conflicts with the HostnameConfig
# doc topf always emits). Matches live exactly: auto=off + static hostname.
# .Node.Host is the FQDN declared in topf.yaml.
---
apiVersion: v1alpha1
kind: HostnameConfig
auto: "off"
hostname: {{ .Node.Host }}

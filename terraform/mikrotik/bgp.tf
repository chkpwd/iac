# BGP peering between MikroTik (AS 64512) and Kubernetes nodes running Cilium (AS 64513).
# Each k8s node gets its own eBGP connection so MikroTik can receive per-node route
# advertisements for LoadBalancer IPs allocated by Cilium from the 10.0.10.0/24 pool.

locals {
  k8s_nodes = {
    "ct-k8s-01" = "10.0.10.10"
    "ct-k8s-02" = "10.0.10.11"
    "ct-k8s-03" = "10.0.10.12"
  }
}

resource "routeros_routing_bgp_connection" "k8s_nodes" {
  for_each = local.k8s_nodes

  name    = "cilium-${each.key}"
  comment = "eBGP peer: Cilium on ${each.key}"

  # MikroTik's ASN
  as = "64512"

  connect = false
  listen  = true

  # Keepalive must be lower than negotiated hold time (90s) to avoid flaps.
  keepalive_time = "30s"
  hold_time      = "1m30s"

  # Rewrite next-hop to MikroTik's own IP so return traffic for DSR
  # passes through the router and stays in the connection tracking table.
  nexthop_choice = "force-self"

  local {
    role    = "ebgp"
    address = "10.0.10.1"
  }

  remote {
    address = each.value
    as      = "64513"
    port    = 179
  }
}

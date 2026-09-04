locals {
  leases     = jsondecode(file("${path.module}/leases.json"))
  lease_addr = { for l in concat(local.leases.guest, local.leases.iot, local.leases.lan) : l.name => l.address }

  address_list = [
    { address = "10.0.10.0/24", comment = "LAN", list = "LAN" },
    { address = "10.0.0.0/8", comment = "rfc1918", list = "private_addr" },
    { address = "172.16.0.0/12", comment = "rfc1918", list = "private_addr" },
    { address = "192.168.0.0/16", comment = "rfc1918", list = "private_addr" },
    { address = local.lease_addr["hisense-android-tv"], comment = "hisense-android-tv", list = "media_clients" },
    { address = local.lease_addr["print-srv-01"], comment = "print-srv-01", list = "iot_wan_allow" },
    { address = local.lease_addr["haos"], comment = "haos", list = "iot_wan_allow" },
    { address = local.lease_addr["rk-doorbell"], comment = "rk-doorbell", list = "iot_wan_allow" },
    { address = local.lease_addr["rk-cx810-02"], comment = "rk-cx810-02", list = "iot_wan_allow" },
    { address = local.lease_addr["rk-trackmix-01"], comment = "rk-trackmix-01", list = "iot_wan_allow" },
    { address = local.lease_addr["enphase-envoy"], comment = "enphase-envoy", list = "iot_wan_allow" },
    { address = local.lease_addr["dreame_vacuum"], comment = "dreame_vacuum", list = "iot_wan_allow" },
    { address = local.lease_addr["hisense-android-tv"], comment = "hisense-android-tv", list = "iot_wan_allow" },
  ]

  # - Uses stable map keys (not array indices) so adding/removing rules doesn't cascade changes
  nat_rules = {
    ont_access     = { order = 5, chain = "srcnat", action = "masquerade", comment = "ONT 8311 access", dst_address = "192.168.11.1", out_interface_list = "WAN" }
    masquerade     = { order = 10, chain = "srcnat", action = "masquerade", ipsec_policy = "out,none", out_interface_list = "WAN" }
    snat_cilium_lb = { order = 15, chain = "srcnat", action = "masquerade", comment = "asymmetric routing fix", dst_address = "10.0.45.0/24", src_address_list = "private_addr" }
    cilium         = { order = 20, chain = "dstnat", action = "dst-nat", in_interface_list = "WAN", protocol = "tcp", dst_port = "443", to_addresses = "10.0.45.31", to_ports = "443", comment = "cilium ingress" }
    qbittorrent    = { order = 40, chain = "dstnat", action = "dst-nat", in_interface_list = "WAN", protocol = "tcp", dst_port = "50413", to_addresses = "10.0.45.34", to_ports = "50413", comment = "qbittorrent" }
  }

  nat_rules_map = {
    for k, v in local.nat_rules :
    format("%04d-%s", v.order, k) => merge(v, { key = k })
  }

  # Order field controls rule sequence; spaced by 10 to allow inserting new rules.
  firewall_filter_rules = {
    input_drop_invalid               = { order = 10, chain = "input", action = "drop", comment = "drop invalid", connection_state = "invalid" }
    input_accept_established         = { order = 20, chain = "input", action = "accept", comment = "accept established,related,untracked", connection_state = "established,related,untracked" }
    input_allow_wireguard_udp        = { order = 30, chain = "input", action = "accept", comment = "allow WireGuard UDP", protocol = "udp", dst_port = "53834" }
    input_allow_wireguard_peers      = { order = 40, chain = "input", action = "accept", comment = "allow router access from WireGuard subnet", src_address = "10.6.6.0/24" }
    input_accept_icmp                = { order = 50, chain = "input", action = "accept", comment = "accept ICMP", protocol = "icmp" }
    input_accept_loopback            = { order = 60, chain = "input", action = "accept", comment = "accept to local loopback (for CAPsMAN)", dst_address = "127.0.0.1" }
    input_allow_dhcp_iot             = { order = 70, chain = "input", action = "accept", comment = "allow DHCP from IoT", protocol = "udp", dst_port = "67,68", in_interface = "iot" }
    input_allow_dns_iot_udp          = { order = 72, chain = "input", action = "accept", comment = "allow IoT DNS to router (UDP)", protocol = "udp", dst_address = var.dns_ip, dst_port = "53", in_interface = "iot" }
    input_allow_dns_iot_tcp          = { order = 74, chain = "input", action = "accept", comment = "allow IoT DNS to router (TCP)", protocol = "tcp", dst_address = var.dns_ip, dst_port = "53", in_interface = "iot" }
    input_allow_dhcp_guest           = { order = 80, chain = "input", action = "accept", comment = "allow DHCP from Guest", protocol = "udp", dst_port = "67,68", in_interface = "guest" }
    input_allow_dns_guest_udp        = { order = 82, chain = "input", action = "accept", comment = "allow Guest DNS to router (UDP)", protocol = "udp", dst_address = var.dns_ip, dst_port = "53", in_interface = "guest" }
    input_allow_dns_guest_tcp        = { order = 84, chain = "input", action = "accept", comment = "allow Guest DNS to router (TCP)", protocol = "tcp", dst_address = var.dns_ip, dst_port = "53", in_interface = "guest" }
    input_drop_not_lan               = { order = 90, chain = "input", action = "drop", comment = "drop all not coming from LAN", in_interface_list = "!LAN" }
    forward_drop_invalid             = { order = 100, chain = "forward", action = "drop", comment = "drop invalid", connection_state = "invalid" }
    forward_fasttrack                = { order = 110, chain = "forward", action = "fasttrack-connection", comment = "fasttrack", connection_state = "established,related", hw_offload = true }
    forward_accept_established       = { order = 120, chain = "forward", action = "accept", comment = "accept established,related, untracked", connection_state = "established,related,untracked" }
    forward_accept_ipsec_in          = { order = 130, chain = "forward", action = "accept", comment = "accept in ipsec policy", ipsec_policy = "in,ipsec" }
    forward_accept_ipsec_out         = { order = 140, chain = "forward", action = "accept", comment = "accept out ipsec policy", ipsec_policy = "out,ipsec" }
    forward_allow_wg_gatus_icmp_only = { order = 150, chain = "forward", action = "drop", comment = "drop all but icmp from WireGuard peer", protocol = "!icmp", src_address = "10.6.6.4" }
    forward_wan_dstnat_to_k8s_lb     = { order = 165, chain = "forward", action = "accept", comment = "allow DSTNATed WAN to k8s LB IPs", connection_nat_state = "dstnat", dst_address = "10.0.45.0/24", in_interface_list = "WAN" }
    forward_iot_ntp                  = { order = 215, chain = "forward", action = "accept", comment = "allow iot NTP to WAN (clock sync)", protocol = "udp", dst_port = "123", in_interface = "iot", out_interface_list = "WAN" }
    forward_iot_wan                  = { order = 220, chain = "forward", action = "accept", comment = "allow iot to WAN (allow-list only)", in_interface = "iot", out_interface_list = "WAN", src_address_list = "iot_wan_allow" }
    forward_ha_media_clients         = { order = 225, chain = "forward", action = "accept", comment = "allow home assistant to media_clients", protocol = "tcp", src_address = "10.0.20.4", dst_address_list = "media_clients", in_interface = "iot" }
    forward_jellyfin_media_clients   = { order = 226, chain = "forward", action = "accept", comment = "allow jellyfin from media_clients", protocol = "tcp", dst_address = "10.0.45.37", dst_port = "8096", src_address_list = "media_clients", in_interface = "iot" }
    forward_immich_media_clients     = { order = 227, chain = "forward", action = "accept", comment = "allow immich from media_clients", protocol = "tcp", dst_address = "10.0.45.38", dst_port = "2283", src_address_list = "media_clients", in_interface = "iot" }
    forward_iot_drop_local           = { order = 230, chain = "forward", action = "drop", comment = "drop local access on iot net", dst_address_list = "private_addr", in_interface = "iot" }
    forward_iot_drop_all             = { order = 240, chain = "forward", action = "drop", comment = "drop all other forward from iot", in_interface = "iot" }
    forward_guest_ha_tcp             = { order = 310, chain = "forward", action = "accept", comment = "allow home assistant from guest", protocol = "tcp", dst_address = "10.0.20.4", dst_port = "8123", in_interface = "guest" }
    forward_ha_sonarr                = { order = 325, chain = "forward", action = "accept", comment = "allow home assistant to sonarr", protocol = "tcp", src_address = "10.0.20.4", dst_address = "10.0.45.31", dst_port = "443", tls_host = "sonarr.chkpwd.com" }
    forward_ha_radarr                = { order = 326, chain = "forward", action = "accept", comment = "allow home assistant to radarr", protocol = "tcp", src_address = "10.0.20.4", dst_address = "10.0.45.31", dst_port = "443", tls_host = "radarr.chkpwd.com" }
    forward_guest_wan                = { order = 420, chain = "forward", action = "accept", comment = "allow guest -> WAN", in_interface = "guest", out_interface_list = "WAN" }
    forward_guest_drop_local         = { order = 430, chain = "forward", action = "drop", comment = "drop local access on guest net", dst_address_list = "private_addr", in_interface = "guest" }
    forward_guest_drop_all           = { order = 440, chain = "forward", action = "drop", comment = "drop all other forward from guest", in_interface = "guest" }
    forward_drop_wan_not_dstnat      = { order = 500, chain = "forward", action = "drop", comment = "drop all from WAN not DSTNATed", connection_nat_state = "!dstnat", connection_state = "new", in_interface_list = "WAN" }
  }

  # Transforms rules into lexicographically sortable keys for for_each.
  # Key format: "0010-input_accept_established" ensures correct ordering.
  filter_rules_map = {
    for k, v in local.firewall_filter_rules :
    format("%04d-%s", v.order, k) => merge(v, { key = k })
  }
}

resource "routeros_ip_firewall_addr_list" "this" {
  for_each = { for addr in local.address_list : "${addr.list}_${addr.address}" => addr }

  address = each.value.address
  comment = each.value.comment
  list    = each.value.list
}

resource "routeros_ip_firewall_nat" "nat_rules" {
  for_each = local.nat_rules_map

  chain              = each.value.chain
  action             = each.value.action
  comment            = try(each.value.comment, null)
  protocol           = try(each.value.protocol, null)
  dst_port           = try(each.value.dst_port, null)
  dst_address        = try(each.value.dst_address, null)
  src_address_list   = try(each.value.src_address_list, null)
  to_addresses       = try(each.value.to_addresses, null)
  to_ports           = try(each.value.to_ports, null)
  in_interface_list  = try(each.value.in_interface_list, null)
  out_interface_list = try(each.value.out_interface_list, null)
  ipsec_policy       = try(each.value.ipsec_policy, null)

  lifecycle {
    create_before_destroy = true
  }
}

resource "routeros_move_items" "nat_rules" {
  count = length(local.nat_rules) > 0 ? 1 : 0

  resource_path = "/ip/firewall/nat"
  sequence      = [for idx in sort(keys(local.nat_rules_map)) : routeros_ip_firewall_nat.nat_rules[idx].id]

  depends_on = [routeros_ip_firewall_nat.nat_rules]
}

# Filter rules use create_before_destroy so new rules are created before
# old ones are removed. Ordering is handled separately by routeros_move_items.
resource "routeros_ip_firewall_filter" "filter_rules" {
  for_each = local.filter_rules_map

  chain   = each.value.chain
  action  = each.value.action
  comment = coalesce(try(each.value.comment, null), "Managed by Terraform - ${each.value.key}")

  connection_state     = try(each.value.connection_state, null)
  protocol             = try(each.value.protocol, null)
  dst_address          = try(each.value.dst_address, null)
  dst_port             = try(each.value.dst_port, null)
  in_interface         = try(each.value.in_interface, null)
  in_interface_list    = try(each.value.in_interface_list, null)
  out_interface_list   = try(each.value.out_interface_list, null)
  dst_address_list     = try(each.value.dst_address_list, null)
  connection_nat_state = try(each.value.connection_nat_state, null)
  ipsec_policy         = try(each.value.ipsec_policy, null)
  hw_offload           = try(each.value.hw_offload, null)
  src_address          = try(each.value.src_address, null)
  src_address_list     = try(each.value.src_address_list, null)
  tls_host             = try(each.value.tls_host, null)

  depends_on = [routeros_ip_firewall_addr_list.this]

  lifecycle {
    create_before_destroy = true
  }
}

resource "routeros_move_items" "filter_rules" {
  count = length(local.firewall_filter_rules) > 0 ? 1 : 0

  resource_path = "/ip/firewall/filter"
  sequence      = [for idx in sort(keys(local.filter_rules_map)) : routeros_ip_firewall_filter.filter_rules[idx].id]

  depends_on = [routeros_ip_firewall_filter.filter_rules]
}

locals {
  address_list = [
    { address = "10.0.10.0/24", comment = "LAN", list = "LAN" },
    { address = "10.0.0.0/8", comment = "rfc1918", list = "private_addr" },
    { address = "172.16.0.0/12", comment = "rfc1918", list = "private_addr" },
    { address = "192.168.0.0/16", comment = "rfc1918", list = "private_addr" },
    { address = "10.0.30.2", comment = "plex access", list = "media_clients" },
    { address = "10.0.30.3", comment = "plex access", list = "media_clients" },
    { address = "10.0.30.5", comment = "plex access", list = "media_clients" },
    { address = "10.0.30.17", comment = "plex access", list = "media_clients" },
  ]

  # - Uses stable map keys (not array indices) so adding/removing rules doesn't cascade changes
  nat_rules = {
    masquerade  = { order = 10, chain = "srcnat", action = "masquerade", ipsec_policy = "out,none", out_interface_list = "WAN" }
    cilium      = { order = 20, chain = "dstnat", action = "dst-nat", in_interface_list = "WAN", protocol = "tcp", dst_port = "443", to_addresses = "10.0.10.31", to_ports = "443", comment = "cilium ingress" }
    plex        = { order = 30, chain = "dstnat", action = "dst-nat", in_interface_list = "WAN", protocol = "tcp", dst_port = "32400", to_addresses = "10.0.10.35", to_ports = "32400", comment = "plex" }
    qbittorrent = { order = 40, chain = "dstnat", action = "dst-nat", in_interface_list = "WAN", protocol = "tcp", dst_port = "50413", to_addresses = "10.0.10.34", to_ports = "50413", comment = "qbittorrent" }
  }

  nat_rules_map = {
    for k, v in local.nat_rules :
    format("%04d-%s", v.order, k) => merge(v, { key = k })
  }

  # Order field controls rule sequence; spaced by 10 to allow inserting new rules.
  firewall_filter_rules = {
    input_accept_established   = { order = 10, chain = "input", action = "accept", comment = "accept established,related,untracked", connection_state = "established,related,untracked" }
    input_drop_invalid         = { order = 20, chain = "input", action = "drop", comment = "drop invalid", connection_state = "invalid" }
    input_accept_icmp          = { order = 30, chain = "input", action = "accept", comment = "accept ICMP", protocol = "icmp" }
    input_accept_loopback      = { order = 40, chain = "input", action = "accept", comment = "accept to local loopback (for CAPsMAN)", dst_address = "127.0.0.1" }
    input_allow_dhcp_iot       = { order = 50, chain = "input", action = "accept", comment = "allow DHCP from IoT", protocol = "udp", dst_port = "67,68", in_interface = "iot" }
    input_allow_dhcp_guest     = { order = 60, chain = "input", action = "accept", comment = "allow DHCP from Guest", protocol = "udp", dst_port = "67,68", in_interface = "guest" }
    input_drop_not_lan         = { order = 70, chain = "input", action = "drop", comment = "drop all not coming from LAN", in_interface_list = "!LAN" }
    forward_accept_ipsec_in    = { order = 100, chain = "forward", action = "accept", comment = "accept in ipsec policy", ipsec_policy = "in,ipsec" }
    forward_accept_ipsec_out   = { order = 110, chain = "forward", action = "accept", comment = "accept out ipsec policy", ipsec_policy = "out,ipsec" }
    forward_accept_established = { order = 120, chain = "forward", action = "accept", comment = "accept established,related, untracked", connection_state = "established,related,untracked" }
    forward_fasttrack          = { order = 130, chain = "forward", action = "fasttrack-connection", comment = "fasttrack", connection_state = "established,related", hw_offload = true }
    forward_iot_dns_udp        = { order = 200, chain = "forward", action = "accept", comment = "iot allow DNS (UDP)", protocol = "udp", dst_address = var.dns_ip, dst_port = "53", in_interface = "iot" }
    # forward_iot_dns_tcp         = { order = 210, chain = "forward", action = "accept", comment = "iot allow DNS (TCP)", protocol = "tcp", dst_address = var.dns_ip, dst_port = "53", in_interface = "iot" }
    forward_iot_wan             = { order = 220, chain = "forward", action = "accept", comment = "iot -> WAN allow", in_interface = "iot", out_interface_list = "WAN" }
    forward_iot_drop_local      = { order = 230, chain = "forward", action = "drop", comment = "drop local access on iot net", dst_address_list = "private_addr", in_interface = "iot" }
    forward_plex_guest          = { order = 300, chain = "forward", action = "accept", comment = "allow plex from media_clients", protocol = "tcp", dst_address = "10.0.10.35", dst_port = "32400", src_address_list = "media_clients", in_interface = "guest" }
    forward_guest_dns_udp       = { order = 400, chain = "forward", action = "accept", comment = "guest allow DNS (UDP)", protocol = "udp", dst_address = var.dns_ip, dst_port = "53", in_interface = "guest" }
    forward_guest_dns_tcp       = { order = 410, chain = "forward", action = "accept", comment = "guest allow DNS (TCP)", protocol = "tcp", dst_address = var.dns_ip, dst_port = "53", in_interface = "guest" }
    forward_guest_wan           = { order = 420, chain = "forward", action = "accept", comment = "guest -> WAN allow", in_interface = "guest", out_interface_list = "WAN" }
    forward_guest_drop_local    = { order = 430, chain = "forward", action = "drop", comment = "drop local access on guest net", dst_address_list = "private_addr", in_interface = "guest" }
    forward_guest_drop_all      = { order = 500, chain = "forward", action = "drop", comment = "guest drop all other forward", in_interface = "guest" }
    forward_iot_drop_all        = { order = 510, chain = "forward", action = "drop", comment = "iot drop all other forward", in_interface = "iot" }
    forward_drop_invalid        = { order = 520, chain = "forward", action = "drop", comment = "drop invalid", connection_state = "invalid" }
    forward_drop_wan_not_dstnat = { order = 530, chain = "forward", action = "drop", comment = "drop all from WAN not DSTNATed", connection_nat_state = "!dstnat", connection_state = "new", in_interface_list = "WAN" }
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

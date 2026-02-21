locals {
  address_list_map = {
    for idx, rule in var.address_list : format("%00004d", idx) => rule
  }

  firewall_filter_rules = [
    { chain = "input", action = "accept", comment = "accept established,related,untracked", connection_state = "established,related,untracked" },
    { chain = "input", action = "drop", comment = "drop invalid", connection_state = "invalid" },
    { chain = "input", action = "accept", comment = "accept ICMP", protocol = "icmp" },
    { chain = "input", action = "accept", comment = "accept to local loopback (for CAPsMAN)", dst_address = "127.0.0.1" },
    { chain = "input", action = "accept", comment = "allow DHCP from IoT", protocol = "udp", dst_port = "67,68", in_interface = "iot" },
    { chain = "input", action = "accept", comment = "allow DHCP from Guest", protocol = "udp", dst_port = "67,68", in_interface = "guest" },
    { chain = "input", action = "drop", comment = "drop all not coming from LAN", in_interface_list = "!LAN" },

    { chain = "forward", action = "accept", comment = "accept in ipsec policy", ipsec_policy = "in,ipsec" },
    { chain = "forward", action = "accept", comment = "accept out ipsec policy", ipsec_policy = "out,ipsec" },
    { chain = "forward", action = "accept", comment = "accept established,related, untracked", connection_state = "established,related,untracked" },
    { chain = "forward", action = "fasttrack-connection", comment = "fasttrack", connection_state = "established,related", hw_offload = true },

    { chain = "forward", action = "accept", comment = "iot allow DNS (UDP)", protocol = "udp", dst_address = var.dns_ip, dst_port = "53", in_interface = "iot" },
    { chain = "forward", action = "accept", comment = "iot allow DNS (TCP)", protocol = "tcp", dst_address = var.dns_ip, dst_port = "53", in_interface = "iot" },
    { chain = "forward", action = "accept", comment = "iot -> WAN allow", in_interface = "iot", out_interface_list = "WAN" },
    { chain = "forward", action = "drop", comment = "drop local access on iot net", dst_address_list = "private_addr", in_interface = "iot" },

    { chain = "forward", action = "accept", comment = "guest allow DNS (UDP)", protocol = "udp", dst_address = var.dns_ip, dst_port = "53", in_interface = "guest" },
    { chain = "forward", action = "accept", comment = "guest allow DNS (TCP)", protocol = "tcp", dst_address = var.dns_ip, dst_port = "53", in_interface = "guest" },
    { chain = "forward", action = "accept", comment = "guest -> WAN allow", in_interface = "guest", out_interface_list = "WAN" },
    { chain = "forward", action = "drop", comment = "drop local access on guest net", dst_address_list = "private_addr", in_interface = "guest" },

    { chain = "forward", action = "drop", comment = "guest drop all other forward", in_interface = "guest" },
    { chain = "forward", action = "drop", comment = "iot drop all other forward", in_interface = "iot" },
    { chain = "forward", action = "drop", comment = "drop invalid", connection_state = "invalid" },
    { chain = "forward", action = "drop", comment = "drop all from WAN not DSTNATed", connection_nat_state = "!dstnat", connection_state = "new", in_interface_list = "WAN" },
  ]

  firewall_filter_rule_map = {
    for idx, r in local.firewall_filter_rules : format("%0003d", idx) => r
  }
}

resource "routeros_ip_firewall_addr_list" "address_list" {
  for_each = local.address_list_map

  address  = each.value.address
  comment  = each.value.comment
  disabled = each.value.disabled
  list     = each.value.list
}

resource "routeros_ip_firewall_nat" "masquerade" {
  action             = "masquerade"
  chain              = "srcnat"
  ipsec_policy       = "out,none"
  out_interface_list = routeros_interface_list.wan.name
}

resource "routeros_ip_firewall_filter" "filter_rules" {
  for_each = local.firewall_filter_rule_map

  chain   = each.value.chain
  action  = each.value.action
  comment = each.value.comment

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

  depends_on = [routeros_ip_firewall_addr_list.address_list]
}

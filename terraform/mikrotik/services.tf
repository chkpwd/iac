resource "routeros_system_ntp_client" "pool" {
  enabled = true
  mode    = "unicast"
  servers = ["pool.ntp.org"]
}

resource "routeros_system_identity" "identity" {
  name = "rt-mgmt"
}

resource "routeros_system_certificate" "local-root-ca-cert" {
  name        = "local-root-cert"
  common_name = "local-cert"
  key_size    = "prime256v1"
  key_usage   = ["key-cert-sign", "crl-sign"]
  trusted     = true
  sign {}

  lifecycle { ignore_changes = [sign] }
}

resource "routeros_system_certificate" "ss-web-cert" {
  name        = "ss-web-cert"
  common_name = "10.0.10.1"

  country      = "US"
  organization = "chkpwd"
  days_valid   = 3650

  key_usage = ["key-cert-sign", "crl-sign", "digital-signature", "key-agreement", "tls-server"]
  key_size  = "prime256v1"

  trusted = true
  sign { ca = routeros_system_certificate.local-root-ca-cert.name }

  lifecycle { ignore_changes = [sign] }
}

resource "routeros_ip_service" "disabled" {
  for_each = { for service in var.disabled_services : service.name => service }

  numbers  = each.value.name
  port     = each.value.port
  disabled = true
}

resource "routeros_ip_service" "enabled" {
  for_each = { for service in var.enabled_services : service.name => service }

  numbers  = each.value.name
  port     = each.value.port
  disabled = false
}

resource "routeros_ip_service" "ssl" {
  for_each = { "api-ssl" = 8729, "www-ssl" = 443 }

  numbers     = each.key
  port        = each.value
  tls_version = "only-1.2"
  certificate = routeros_system_certificate.ss-web-cert.name
}

resource "routeros_dns" "dns-server" {
  allow_remote_requests = true
  servers               = ["1.1.1.1", "8.8.8.8"]
}

resource "routeros_ipv6_settings" "disable" {
  disable_ipv6 = "true"
}

resource "routeros_tool_mac_server_winbox" "winbox_mac_access" {
  allowed_interface_list = routeros_interface_list.lan.name
}

resource "routeros_tool_mac_server" "mac_server" {
  allowed_interface_list = routeros_interface_list.lan.name
}

resource "routeros_ip_neighbor_discovery_settings" "lan_discovery" {
  discover_interface_list = routeros_interface_list.lan.name
}

resource "routeros_system_clock" "timezone" {
  time_zone_name       = "America/New_York"
  time_zone_autodetect = false
}

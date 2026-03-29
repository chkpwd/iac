output "dns_name" {
  description = "The DDNS hostname assigned by MikroTik cloud (e.g. <id>.sn.mynetname.net)"
  value       = routeros_ip_cloud.this.dns_name
}

output "wireguard_interface_pubkey" {
  description = "Wireguard Interface Public Key"
  value       = routeros_interface_wireguard.this.public_key
}

output "public_address" {
  description = "The public IPv4 address reported by MikroTik cloud"
  value       = routeros_ip_cloud.this.public_address
}

output "gatus_wg_peer_pubkey" {
  description = "The public key of the Gatus Wireguard Peer"
  value       = nonsensitive(routeros_wireguard_keys.wgk.keys[2].public)
}

output "gatus_wg_peer_privkey" {
  description = "The private key of the Gatus Wireguard Peer"
  value       = routeros_wireguard_keys.wgk.keys[2].private
  sensitive   = true
}

output "dns_name" {
  description = "The DDNS hostname assigned by MikroTik cloud (e.g. <id>.sn.mynetname.net)"
  value       = routeros_ip_cloud.this.dns_name
}
output "public_address" {
  description = "The public IPv4 address reported by MikroTik cloud"
  value       = routeros_ip_cloud.this.public_address
}

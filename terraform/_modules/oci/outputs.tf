output "public_ip" {
  description = "Oracle Cloud instance public IP address"
  value       = oci_core_instance.instance.public_ip != null ? oci_core_instance.instance.public_ip : null
}

output "nsg_id" {
  description = "Network Security Group ID"
  value       = oci_core_network_security_group.nsg.id
}

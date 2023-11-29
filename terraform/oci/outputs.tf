output "ct-01-oci_public_ip" {
  value = module.ct-01-oci.public_ip
}

output "ct-02-oci_public_ip" {
  value = module.ct-02-oci.public_ip
}

output "ct-02-oci_nsg_id" {
  value = module.ct-02-oci.nsg_id
}

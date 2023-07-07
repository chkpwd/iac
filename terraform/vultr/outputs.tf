output "fedora_hats_hostname" {
  value = {
    for instance in vultr_instance.fedora_hats : instance.id => instance.hostname
  }
}
output "fedora_hats_ipv6_address" {
  value = {
    for instance in vultr_instance.fedora_hats : instance.id => instance.main_ip
  }

}

output "rocks_hostname" {
  value = vultr_instance.rocks.*.hostname
}

output "rocks_main_ip" {
  value = vultr_instance.rocks.*.hostname
}
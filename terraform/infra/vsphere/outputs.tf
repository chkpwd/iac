output "rocks_hostname" {
  value = vultr_instance.rocks.*.hostname
}

output "rocks_main_ip" {
  value = vultr_instance.rocks.*.hostname
}
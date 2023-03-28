output "hostname" {
  value = {
    for instance in vultr_instance.instances :
      instance.id => instance.hostname
  }
}
output "ipv6_address" {
  value = {
    for instance in vultr_instance.instances :
      instance.id => instance.main_ip
  }
}
output "guest_hostname" {
    value = vsphere_virtual_machine.main.name
}

output "ipv4_address" {
    value = vsphere_virtual_machine.main.default_ip_address
}

output "mac_address" {
    value = vsphere_virtual_machine.main.network_interface[0].mac_address 
}
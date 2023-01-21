module "ansible-vm" {
 source      = "./modules/ansible-test"
 vm_count = 3
 ssh_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICsJocZS/OZ/4ZrLAxFOppiVMTym5oDkfHiir3YFg8mQ"
 vm_user = "hyoga"
 ip_address = "172.16.16.20"
 gateway = "172.16.16.1"
 bridge = "vmbr0"
 disk_size = 15
 cpu_count = 2
 ram_size = 2048
 storage_location = "Arenas"
 vlan_tag = "0"
 vm_name = "ansible-vm"
}
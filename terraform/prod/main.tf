module "horizon" {
  source                    = "../modules/vsphere"
  vm_name                   = "horizon"
  vm_cpu                    = 2
  vm_ram                    = 4096
  vm_template               = "deb-x11-template"
  vm_ip                     = "172.16.16.10"
  vm_netmask                = "24"
  vm_network                = "LAN"
  vm_gateway                = "172.16.16.1"
  vm_dns                    = var.vm_dns
  vm_public_key             = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBK2VnKgOX7i1ISETheqjAO3/xo6D9n7QbWyfDAPsXwa hyoga@lifeline"
  vsphere_user              = var.vsphere_user
  vsphere_password          = var.vsphere_password
}

module "stable-diffusion" {
  source                    = "../modules/vsphere"
  vm_name                   = "stable-diffusion"
  vm_cpu                    = 4
  vm_ram                    = 10240
  vm_network                = "Public"
  vm_template               = "deb-x11-template"
  vm_ip                     = "172.16.20.10"
  vm_netmask                = "24"
  vm_gateway                = "172.16.20.1"
  vm_dns                    = var.vm_dns
  vm_public_key             = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBK2VnKgOX7i1ISETheqjAO3/xo6D9n7QbWyfDAPsXwa hyoga@lifeline"
  vsphere_user              = var.vsphere_user
  vsphere_password          = var.vsphere_password
}

module "crypto" {
  source                    = "../modules/vsphere"
  vm_name                   = "crypto"
  vm_cpu                    = 4
  vm_disk_size              = "48"
  vm_ram                    = 4096
  vm_network                = "LAN"
  vm_template               = "deb-x11-template"
  vm_ip                     = "172.16.16.12"
  vm_netmask                = "24"
  vm_gateway                = "172.16.16.1"
  vm_dns                    = var.vm_dns
  vm_public_key             = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBK2VnKgOX7i1ISETheqjAO3/xo6D9n7QbWyfDAPsXwa hyoga@lifeline"
  vsphere_user              = var.vsphere_user
  vsphere_password          = var.vsphere_password
}

module "mirage" {
  source                    = "../modules/vsphere"
  vm_name                   = "mirage"
  vm_cpu                    = 2
  vm_ram                    = 8192
  vm_network                = "IoT"
  vm_template               = "deb-x11-template"
  vm_ip                     = "172.16.10.20"
  vm_netmask                = "24"
  vm_gateway                = "172.16.10.1"
  vm_dns                    = var.vm_dns
  vm_public_key             = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBK2VnKgOX7i1ISETheqjAO3/xo6D9n7QbWyfDAPsXwa hyoga@lifeline"
  vsphere_user              = var.vsphere_user
  vsphere_password          = var.vsphere_password
}

module "homeassistant" {
  source                    = "../modules/vsphere"
  vm_name                   = "valkyrie"
  vm_cpu                    = 2
  vm_ram                    = 4096
  vm_network                = "LAN"
  vm_template               = "deb-x11-template"
  vm_ip                     = "172.16.16.11"
  vm_netmask                = "24"
  vm_gateway                = "172.16.16.1"
  vm_dns                    = var.vm_dns
  vm_public_key             = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBK2VnKgOX7i1ISETheqjAO3/xo6D9n7QbWyfDAPsXwa crypto"
  vsphere_user              = var.vsphere_user
  vsphere_password          = var.vsphere_password
}

module "kubes-control-plane" {
  source                    = "../modules/vsphere"
  for_each                  = toset(["1", "2", "3"])
  vm_name                   = "kubes-master-${each.key}"
  vm_cpu                    = 2
  vm_ram                    = 2048
  vm_network                = "LAN"
  vm_template               = "deb-x11-template"
  vm_ip                     = "172.16.16.23${each.key}"
  vm_netmask                = "24"
  vm_gateway                = "172.16.16.1"
  vm_dns                    = var.vm_dns
  vm_public_key             = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBK2VnKgOX7i1ISETheqjAO3/xo6D9n7QbWyfDAPsXwa crypto"
  vsphere_user              = var.vsphere_user
  vsphere_password          = var.vsphere_password
}

module "kubes-worker-nodes" {
  source                    = "../modules/vsphere"
  for_each                  =  toset([for n in range(4, 6) : tostring(n)])
  vm_name                   = "kubes-worker-${each.key}"
  vm_cpu                    = 2
  vm_ram                    = 2048
  vm_network                = "LAN"
  vm_template               = "deb-x11-template"
  vm_ip                     = "172.16.16.23${each.key}"
  #vm_ip                     = "172.16.16.23${format("%2d", each.value + 1)}"
  vm_netmask                = "24"
  vm_gateway                = "172.16.16.1"
  vm_dns                    = var.vm_dns
  vm_public_key             = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBK2VnKgOX7i1ISETheqjAO3/xo6D9n7QbWyfDAPsXwa crypto"
  vsphere_user              = var.vsphere_user
  vsphere_password          = var.vsphere_password
}
# module "rocky-linux" {
#   source                    = "../modules/vultr"
#   vultr_api_key             = var.vultr_api_key
# }

# module "proxmox-vm" {
#  source      = "../modules/proxmox"
#  vm_count = 3
#  ssh_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICsJocZS/OZ/4ZrLAxFOppiVMTym5oDkfHiir3YFg8mQ"
#  vm_user = "hyoga"
#  ip_address = "172.16.16.20"
#  gateway = "172.16.16.1"
#  bridge = "vmbr0"
#  disk_size = 15
#  cpu_count = 2
#  ram_size = 2048
#  storage_location = "Arenas"
#  vlan_tag = "0"
#  vm_name = "ansible-vm"
# }

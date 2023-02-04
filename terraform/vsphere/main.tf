module "horizon" {
  source                    = "./modules/vm"
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

module "valkyrie" {
  source                    = "./modules/vm"
  vm_name                   = "valkyrie"
  vm_cpu                    = 1
  vm_ram                    = 512
  vm_network                = "LAN"
  vm_template               = "deb-x11-template"
  vm_ip                     = "172.16.16.11"
  vm_netmask                = "24"
  vm_gateway                = "172.16.16.1"
  vm_dns                    = var.vm_dns
  vm_public_key             = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBK2VnKgOX7i1ISETheqjAO3/xo6D9n7QbWyfDAPsXwa hyoga@lifeline"
  vsphere_user              = var.vsphere_user
  vsphere_password          = var.vsphere_password
}

module "stable-diffusion" {
  source                    = "./modules/vm"
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
  source                    = "./modules/vm-code-server"
  vm_name                   = "crypto"
  vm_cpu                    = 4
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
  ssh_password              = var.ssh_password
}

module "test-vm" {
  source                    = "./modules/vm-code-server"
  vm_name                   = "test-vm"
  vm_cpu                    = 1
  vm_ram                    = 1024
  vm_network                = "LAN"
  vm_template               = "deb-x11-template"
  vm_ip                     = "172.16.16.65"
  vm_netmask                = "24"
  vm_gateway                = "172.16.16.1"
  vm_dns                    = var.vm_dns
  vm_public_key             = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBK2VnKgOX7i1ISETheqjAO3/xo6D9n7QbWyfDAPsXwa hyoga@lifeline"
  vsphere_user              = var.vsphere_user
  vsphere_password          = var.vsphere_password
  ssh_password              = var.ssh_password
}

module "mirage" {
  source                    = "./modules/vm"
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


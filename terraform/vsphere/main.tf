module "horizon" {
  source                    = "./modules/vm"
  vm_name                   = "horizon"
  vm_cpu                    = 2
  vm_ram                    = 4096
  vm_template               = "deb-x11-template"
  vm_ip                     = "172.16.16.59"
  vm_netmask                = "24"
  vm_gateway                = "172.16.16.1"
  vm_dns                    = var.vm_dns
  vm_public_key             = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICsJocZS/OZ/4ZrLAxFOppiVMTym5oDkfHiir3YFg8mQ endeavourOS"
  vsphere_user              = var.vsphere_user
  vsphere_password          = var.vsphere_password
}

module "mirage" {
  source                    = "./modules/vm"
  vm_name                   = "mirage"
  vm_cpu                    = 2
  vm_ram                    = 4096
  vm_template               = "deb-x11-template"
  vm_ip                     = "172.16.10.102"
  vm_netmask                = "24"
  vm_gateway                = "172.16.16.1"
  vm_dns                    = var.vm_dns
  vm_public_key             = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICsJocZS/OZ/4ZrLAxFOppiVMTym5oDkfHiir3YFg8mQ endeavourOS"
  vsphere_user              = var.vsphere_user
  vsphere_password          = var.vsphere_password
}
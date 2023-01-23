module "mirage" {
  source                    = "./modules/mirage"
  vm_name                   = "mirage"
  vm_cpu                    = 1
  vm_ram                    = 1024
  vm_template               = "deb-x11-template-test"
  vm_ip                     = "172.16.16.65"
  vm_netmask                = "24"
  vm_gateway                = "172.16.16.1"
  vm_dns                    = [0,1]
  vm_public_key             = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICsJocZS/OZ/4ZrLAxFOppiVMTym5oDkfHiir3YFg8mQ endeavourOS-test"
  vsphere_user              = var.vsphere_user
  vsphere_password          = var.vsphere_password
}
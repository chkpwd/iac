module "mirage" {
  source                    = "./modules/mirage"
  vm_name                   = "mirage"
  vm_cpu                    = 2
  vm_ram                    = 1024
  vm_datastore              = "datastore"
  vm_network                = "VM Network"
  vm_template               = "deb-x11-template"
  vm_linked_clone           = "false"
  vm_ip                     = "172.16.16.65"
  vm_netmask                = "24"
  vm_gateway                = "172.16.16.1"
  ssh_username              = "hyoga"
  vm_dns                    = [0,1]
  vsphere_datacenter        = "The Outlands"
  vsphere_user              = var.vsphere_user
  vsphere_password          = var.vsphere_password
  vsphere_cluster           = "Eduardo"
  vsphere_unverified_ssl    = "true"
  vm_domain                 = "typhon.tech"
  vm_public_key             = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICsJocZS/OZ/4ZrLAxFOppiVMTym5oDkfHiir3YFg8mQ"
}
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
  vm_dns                    = "${dns_server_list}"
  ssh_username              = ""
  vsphere_user              = ""
  vsphere_password          = ""
  vsphere_datacenter        = ""
  vsphere_cluster           = ""
  vsphere_unverified_ssl    = "true"
  vm_domain                 = ""
  vm_public_key             = ""
}
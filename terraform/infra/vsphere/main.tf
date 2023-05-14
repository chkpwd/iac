#===============================================================================
# vSphere Data
#===============================================================================

# data "vsphere_folder" "cattles" {
#   path = "/The Outlands/vm/cattles"
# }

#===============================================================================
# vSphere Modules
#===============================================================================

# module "cattles_folder" {
#   source                    = "./modules/folders"
# }

module "horizon" {
  source                    = "./modules/guest_machines"
  os_type                   = "linux"
  vm_name                   = "horizon"
  vm_cpu                    = 2
  vm_ram                    = 4096
  vm_template               = "deb-x11-template"
  vm_network                = "LAN"
  # folder_id                 = "${data.vsphere_folder.cattles.path}"
}

module "stable-diffusion" {
  source                    = "./modules/guest_machines"
  os_type                   = "linux"
  vm_name                   = "stable-diffusion"
  vm_cpu                    = 4
  secondary_disks           = false
  vm_pri_disk_size          = 48 
  #vm_sec_disk_size         = 48
  vm_ram                    = 10240
  vm_network                = "IoT"
  vm_template               = "deb-x11-template"
}

module "crypto" {
  source                    = "./modules/guest_machines"
  os_type                   = "linux"
  vm_name                   = "crypto"
  vm_cpu                    = 4
  vm_pri_disk_size          = "48"
  vm_ram                    = 8192
  vm_network                = "LAN"
  vm_template               = "deb-x11-template"
}

module "mirage" {
  source                    = "./modules/guest_machines"
  os_type                   = "linux"
  vm_name                   = "mirage"
  vm_cpu                    = 4
  vm_ram                    = 8192
  vm_network                = "Media"
  vm_template               = "deb-x11-template"
}

module "homeassistant" {
  source                    = "./modules/guest_machines"
  os_type                   = "linux"
  vm_name                   = "valkyrie"
  vm_cpu                    = 2
  vm_ram                    = 2048
  vm_network                = "LAN"
  vm_template               = "deb-x11-template"
}

module "bloodhound" {
  source                    = "./modules/guest_machines"
  count                     = 1
  os_type                   = "windows"
  vm_name                   = "bloodhound"
  vm_cpu                    = 2
  vm_ram                    = 8192
  vm_pri_disk_size          = 48 
  vm_network                = "LAN"
  vm_template               = "WinSrv22-template-DE"
}

module "kube-ops" {
  source                    = "./modules/guest_machines"
  count                     = 3
  os_type                   = "linux"
  vm_name                   = "kubes-cp-${count.index + 1}"
  vm_cpu                    = 2
  vm_ram                    = 4096
  vm_pri_disk_size          = 60 
  vm_network                = "LAN"
  vm_template               = "deb-x11-template"
}

module "traefik" {
  source                    = "./modules/guest_machines"
  count                     = 1
  os_type                   = "linux"
  vm_name                   = "node-01"
  vm_cpu                    = 2
  vm_ram                    = 2048
  vm_pri_disk_size          = 60 
  vm_network                = "LAN"
  vm_template               = "deb-x11-template"
}

module "quark" {
  source                    = "./modules/guest_machines"
  count                     = 1
  os_type                   = "linux"
  vm_name                   = "quark"
  vm_cpu                    = 1
  vm_ram                    = 1024
  vm_pri_disk_size          = 16
  vm_network                = "LAN"
  vm_template               = "deb-x11-template"
}

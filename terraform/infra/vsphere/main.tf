#===============================================================================
# vSphere Modules
#===============================================================================

module "horizon" {
  source                    = "./modules/guest_machines"
  os_type                   = "linux"
  vm_name                   = "horizon"
  vm_template               = "deb-x11-template"
  vm_network                = "LAN"
  spec = {
    cpu                     = 2
    memory                  = 4096
    disk_size               = 16
  }
}

module "stable-diffusion" {
  source                    = "./modules/guest_machines"
  os_type                   = "linux"
  vm_name                   = "stable-diffusion"
  vm_network                = "IoT"
  vm_template               = "deb-x11-template"
  spec = {
    cpu                     = 4
    memory                  = 10240
    disk_size               = 48
  }
}

module "crypto" {
  source                    = "./modules/guest_machines"
  os_type                   = "linux"
  vm_name                   = "crypto"
  vm_network                = "LAN"
  vm_template               = "deb-x11-template"
  spec = {
    cpu                     = 4
    memory                  = 8192
    disk_size               = 48
  }
}

module "mirage" {
  source                    = "./modules/guest_machines"
  os_type                   = "linux"
  vm_name                   = "mirage"
  vm_network                = "Media"
  vm_template               = "deb-x11-template"
  spec = {
    cpu                     = 4
    memory                  = 8192
    disk_size               = 16
  }
}

module "homeassistant" {
  source                    = "./modules/guest_machines"
  os_type                   = "linux"
  vm_name                   = "valkyrie"
  vm_network                = "LAN"
  vm_template               = "deb-x11-template"
  spec = {
    cpu                     = 2
    memory                  = 2048
    disk_size               = 16
  }
}

# module "bloodhound" {
#   source                    = "./modules/guest_machines"
#   count                     = 1
#   os_type                   = "windows"
#   vm_name                   = "bloodhound"
#   vm_network                = "LAN"
#   vm_template               = "WinSrv22-template-DE"
#   spec = {
#     cpu                     = 2
#     memory                  = 8192
#     disk_size               = 48
#   }
# }

module "kube-ops" {
  source                    = "./modules/guest_machines"
  count                     = 3
  os_type                   = "linux"
  vm_name                   = "kubes-cp-${count.index + 1}"
  vm_network                = "LAN"
  vm_template               = "deb-x11-template"
  spec = {
    cpu                     = 2
    memory                  = 4096
    disk_size               = 16
    additional_disks = [
      {
        size                = 60
      }
    ]
  }
}

module "traefik" {
  source                    = "./modules/guest_machines"
  count                     = 1
  os_type                   = "linux"
  vm_name                   = "node-01"
  vm_network                = "LAN"
  vm_template               = "deb-x11-template"
  spec = {
    cpu                     = 2
    memory                  = 2048
    disk_size               = 60
  }
}
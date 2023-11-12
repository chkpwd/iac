#===============================================================================
# vSphere Modules
#===============================================================================

module "cockpit" {
  source                    = "../_modules/vsphere_vm"
  vm_name                   = "cockpit"
  vm_template               = "deb-12-template"
  network_spec = {
    network_id              = "LAN"
  }
  spec = {
    tags                    = [ vsphere_tag.cattle.id, vsphere_tag.linux.id, vsphere_tag.media.id ]
    folder                  = vsphere_folder.media.path
    cpu                     = 2
    memory                  = 1024 * 4
    disk_size               = 48
    additional_disks = [
      {
        size                = null
        datastore_id        = data.vsphere_datastore.media_datastore.id
        attach_disk         = true
      }
    ]
  }
}

module "media-srv-01" {
  source                    = "../_modules/vsphere_vm"
  vm_name                   = "media-srv-01"
  vm_template               = "deb-12-template"
  network_spec = {
    network_id              = "Media"
  }
  spec = {
    tags                    = [ vsphere_tag.cattle.id, vsphere_tag.linux.id, vsphere_tag.media.id, vsphere_tag.docker.id ]
    folder                  = vsphere_folder.media.path
    cpu                     = 2
    memory                  = 1024 * 2
    memory_reservation      = true
    disk_size               = 16
    additional_disks = [
      {
        size                = 25
      }
    ]
  }
}

module "homeassistant" {
  source                    = "../_modules/vsphere_vm"
  vm_name                   = "home-assistant"
  vm_template               = "deb-12-template"
  network_spec = {
    network_id              = "LAN"
  }
  spec = {
    tags                    = [ vsphere_tag.cattle.id, vsphere_tag.linux.id, vsphere_tag.docker.id ]
    folder                  = vsphere_folder.personal_linux.path
    cpu                     = 4
    memory                  = 1024 * 4
    disk_size               = 16
    additional_disks = [ 
      {
        size                = 25
      } 
    ]
  }
}

module "win-srv-2022" {
  source                    = "../_modules/vsphere_vm"
  count                     = 1
  vm_name                   = "win-srv-2022"
  vm_template               = "WSrv22-DE-Temp"
  network_spec = {
    network_id              = "IoT"
  }
  spec = {
    tags                    = [ vsphere_tag.cattle.id, vsphere_tag.windows.id ]
    folder                  = vsphere_folder.windows.path
    cpu                     = 4
    memory                  = 1024 * 8
    disk_size               = 48
    additional_disks = [
      {
        size                = 100
      }
    ]
  }
}

module "hosting-srv-01" {
  source                    = "../_modules/vsphere_vm"
  vm_name                   = "hosting-srv-01"
  vm_template               = "deb-12-template"
  vm_datastore              = "NVME-30C"
  network_spec = {
    network_id              = "Lab"
  }
  spec = {
    tags                    = [ vsphere_tag.cattle.id, vsphere_tag.linux.id, vsphere_tag.docker.id, vsphere_tag.gaming.id ]
    folder                  = vsphere_folder.gaming_linux.path
    cpu                     = 2
    memory                  = 1024 * 12
    disk_size               = 16
    additional_disks = [ 
      {
        size                = 300
      } 
    ]
  }
}

# module "win10-gaming-01" {
#   source                    = "../_modules/vsphere_vm"
#   count                     = 1
#   vm_name                   = "win10-gaming-01"
#   vm_template               = "W10-22H2-Temp"
#   network_spec = {
#     network_id              = "Lab"
#   }
#   spec = {
#     tags                    = [ vsphere_tag.cattle.id, vsphere_tag.windows.id ]
#     folder                  = vsphere_folder.gaming_windows.path
#     cpu                     = 8
#     memory                  = 1024 * 16
#     memory_reservation      = true
#     pci_device              = [ data.vsphere_host_pci_device.nvidia_1050ti.id ]
#     disk_size               = 48
#     scsi_type               = "lsilogic-sas"
#     additional_disks = [
#       {
#         size                = 100
#       }
#     ]
#   }
# }

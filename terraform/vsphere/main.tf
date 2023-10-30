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

module "mirage" {
  source                    = "../_modules/vsphere_vm"
  vm_name                   = "mirage"
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

module "kube-ops" {
  source                    = "../_modules/vsphere_vm"
  count                     = 3
  vm_name                   = "kubes-cp-${count.index + 1}"
  vm_template               = "k3s-deb12"
  vm_datastore              = "NVME-30B"
  network_spec = {
    network_id              = "LAN"
    mac_address             = ["00:50:56:93:8a:b9", "00:50:56:93:35:60", "00:50:56:93:fa:88"][count.index]
    static_mac_addr         = true
  }
  spec = {
    tags                    = [ vsphere_tag.cattle.id, vsphere_tag.linux.id, vsphere_tag.kubernetes.id ]
    folder                  = vsphere_folder.kubernetes.path
    enable_hv               = true
    cpu                     = 4
    memory                  = 1024 * 24
    disk_size               = 32
    additional_disks = [
      {
        size                = 200
      }
    ]
  }
}

module "dns-srv-02" {
  source                    = "../_modules/vsphere_vm"
  vm_name                   = "dns-srv-02"
  vm_template               = "deb-12-template"
  network_spec = {
    network_id              = "LAN"
  }
  spec = {
    tags                    = [ vsphere_tag.cattle.id, vsphere_tag.linux.id, vsphere_tag.docker.id ]
    folder                  = vsphere_folder.dev.path
    cpu                     = 1
    memory                  = 1024 * 1
    disk_size               = 16
    additional_disks = [ 
      {
        size                = 10
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
    network_id              = "LAN"
  }
  spec = {
    tags                    = [ vsphere_tag.cattle.id, vsphere_tag.linux.id, vsphere_tag.docker.id, vsphere_tag.gaming.id ]
    folder                  = vsphere_folder.gaming_linux.path
    cpu                     = 4
    memory                  = 1024 * 8
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

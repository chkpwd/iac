# module "win-srv-2022" {
#   source                    = "../_modules/vsphere_vm"
#   count                     = 1
#   vm_name                   = "win-srv-2022"
#   vm_template               = "WSRV22-DE-Temp"
#   network_spec = {
#     network_id              = "IOT"
#   }
#   spec = {
#     tags                    = [ vsphere_tag.cattle.id, vsphere_tag.windows.id ]
#     folder                  = vsphere_folder.windows.path
#     cpu                     = 4
#     memory                  = 1024 * 8
#     disk_size               = 48
#     additional_disks = [
#       {
#         size                = 100
#       }
#     ]
#   }
# }

module "test-vm" {
  source                    = "../_modules/vsphere_vm"
  vm_name                   = "test-vm"
  vm_template               = "deb-12-template"
  vm_datastore              = "main-nvme"
  network_spec = {
    network_id              = "LAN"
  }
  spec = {
    tags                    = [ vsphere_tag.cattle.id, vsphere_tag.linux.id ]
    folder                  = vsphere_folder.linux.path
    cpu                     = 2
    memory                  = 1024 * 2
    disk_size               = 16
  }
}
module "win11-gaming-01" {
  source                    = "../_modules/vsphere_vm"
  count                     = 1
  vm_name                   = "win11-gaming-01"
  vm_template               = "W11-22H2-Temp"
  network_spec = {
    network_id              = "IOT"
  }
  spec = {
    tags                    = [ vsphere_tag.cattle.id, vsphere_tag.windows.id, vsphere_tag.gaming.id ]
    folder                  = vsphere_folder.gaming_windows.path
    cpu                     = 8
    memory                  = 1024 * 16
    memory_reservation      = true
    pci_device              = [ data.vsphere_host_pci_device.nvidia_1080.id, data.vsphere_host_pci_device.nvidia_1080_audio.id ]
    disk_size               = 75
    additional_disks = [ 
      {
        size                = 300
      } 
    ]
    scsi_type               = "lsilogic-sas"
    extra_config = {
      "svga.present" = "FALSE"
    }
  }
}

resource "proxmox_virtual_environment_cluster_options" "options" {
  language    = "en"
  keyboard    = "en-us"
  email_from  = "proxmox@chkpwd.com"
  max_workers = 5
}

# module "test-vm-1" {
#   source = "../_modules/proxmox_vm"
#   machine = {
#     name         = "testing-vm-1"
#     id           = 100
#     tags         = ["test1", "test2"]
#     enable_agent = true
#     bios         = "seabios"
#   }

#   spec = {
#     cpu = {
#       cores = 2
#     }
#     memory = {
#       dedicated = 2048
#     }
#     disk = {
#       size         = 32
#       interface    = "scsi0"
#       datastore_id = "prod-nvme"
#       discard      = "on"
#       iothread     = false # only compatible with virtio-scsi-single controller
#       file_id      = proxmox_virtual_environment_download_file.ubuntu_noble_cloud_image.id
#     }
#     network = {
#       bridge = "vmbr10"
#     }
#   }
# }

# module "test-vm-2" {
#   source = "../_modules/proxmox_vm"
#   machine = {
#     name         = "testing-vm-2"
#     id           = 102
#     tags         = ["test1", "test2"]
#     enable_agent = true
#     bios         = "seabios"
#   }

#   spec = {
#     cpu = {
#       cores = 2
#     }
#     memory = {
#       dedicated = 2048
#     }
#     disk = {
#       size         = 32
#       interface    = "scsi0"
#       datastore_id = "prod-nvme"
#       discard      = "on"
#       iothread     = false # only compatible with virtio-scsi-single controller
#       file_id      = proxmox_virtual_environment_download_file.ubuntu_noble_cloud_image.id
#     }
#     network = {
#       bridge = "vmbr10"
#     }

#     # initialization = { # TODO: doesn't work
#     #   user_account = {
#     #     username = "user"
#     #     password = "password"
#     #   }
#     # }
#   }
# }

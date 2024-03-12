resource "proxmox_virtual_environment_cluster_options" "options" {
  language    = "en"
  keyboard    = "en-us"
  email_from  = "proxmox@chkpwd.com"
  max_workers = 5
}

module "test-vm" {
  source = "../_modules/proxmox_vm"
  machine = {
    name = "testing-vm"
    id = 100
    tags = [ "test1", "test2" ]
    enable_agent = true
    bios = "seabios"
  }

  spec = {
    cpu = {
      cores = 2
      hotplugged = 2
    }
    memory = {
      dedicated = 2048
    }
    disk = {
      size = 32
      interface = "scsi0"
    }
    network = {
      bridge = "vmbr0"
    }
  }
}

# module "test-vm" {
#   source = "../_modules/proxmox_clone"
#   machine = {
#     name = "testing-vm-clone"
#     id = 100
#     tags = [ "test1", "test2", "test3" ]
#     enable_agent = true
#     bios = "seabios"
#   }

#   spec = {
#     cpu = {
#       cores = 2
#       hotplugged = 2
#     }
#     memory = {
#       dedicated = 2048
#     }
#     disk = {
#       size = 32
#       interface = "scsi0"
#     }
#     network = {
#       bridge = "vmbr0"
#     }
#   }
# }

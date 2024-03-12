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
  startup = {
    order = 3
    up_delay = 60
    down_delay = 60
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
      cache = "none"
      size = 32
      interface = "scsi0"
      datastore_id = "nvme-pool"
    }
    network = {
      bridge = "vmbr0"
    }
  }
}

variable "node" {
  type    = string
  default = "pve-srv-01"
}

# variable datastore {
#   type = string
#   default = "nvme-pool"
# }

variable "machine" {
  type = object({
    name         = string
    id           = number
    tags         = optional(list(string))
    enable_agent = optional(bool)
    started      = optional(bool)
    on_boot      = optional(bool)
    bios         = optional(string)
    tpm = optional(object({
      datastore_id = optional(string)
      version      = optional(string)
    }))
  })
}

# variable "startup" {
#   type = object({
#     order      = optional(string)
#     up_delay   = optional(string)
#     down_delay = optional(string)
#   })
#   default = {
#     order = null
#     up_delay = null
#     down_delay = null
#   }
# }

variable "spec" {
  type = object({
    cpu = optional(object({
      cores        = optional(number)
      architecture = optional(string)
      flags        = optional(list(string))
      hotplugged   = optional(number)
      type         = optional(string)
    }))
    memory = optional(object({
      dedicated = optional(number)
      floating  = optional(number)
      shared    = optional(number)
    }))
    disk = optional(object({
      cache        = optional(string)
      size         = optional(number)
      discard      = optional(string)
      iothread     = optional(bool)
      file_id      = optional(string)
      file_format  = optional(string)
      interface    = optional(string)
      datastore_id = optional(string)
    }))
    network = optional(object({
      bridge      = optional(string)
      mac_address = optional(string)
      model       = optional(string)
      vlan_id     = optional(number)
    }))
    scsi_hardware = optional(string)
    initialization = optional(object({
      ip_config = object({
        ipv4 = optional(object({
          address = optional(string)
          gateway = optional(string)
        }))
        ipv6 = optional(object({
          address = optional(string)
          gateway = optional(string)
        }))
      })
      user_account = optional(object({
        keys     = optional(string)
        password = optional(string)
        username = optional(string)
      }))
      user_data_file_id = optional(string)
    }))
  })
  default = {
    cpu = {
      cores      = 1
      hotplugged = 0
    }
    memory = {
      dedicated = 1024
    }
    disk = {
      cache        = "none"
      size         = 8
      interface    = "scsi0"
      datastore_id = "nvme-pool"
      iothread     = true
    }
    network = {
      bridge = "vmbr1"
    }
    scsi_hardware = "virtio-scsi-pci"
  }
}

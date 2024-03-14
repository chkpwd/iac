variable node {
  default = "pve-srv-01"
}

variable datastore {
  default = "nvme-pool"
}

variable "machine" {
  type = object({
    name = string
    id   = number
    tags = optional(list(string))
    enable_agent = optional(bool)
    bios = optional(string)
    tpm = optional(object({
      datastore_id = optional(string)
      version = optional(string)
    }))
  })
}

variable "clone" {
  type = object({
    vm_id = number
    full = optional(bool)
    datastore_id = optional(string)
    node_name = optional(string)
    retries = optional(number)
  })
  default = {
    full = true
    retries = 1
  }
}

variable "startup" {
  type = object({
    order      = optional(string)
    up_delay   = optional(string)
    down_delay = optional(string)
  })
  default = {
    order = null
    up_delay = null
    down_delay = null
  }
}

variable "spec" {
  type = object({
    cpu = optional(object({
      cores = optional(number)
      architecture = optional(string)
      flags = optional(list(string))
      hotplugged = optional(number)
      type = optional(string)
    }))
    memory = object({
      dedicated = optional(number)
      floating = optional(number)
      shared = optional(number)
    })
    disk = optional(object({
      cache = optional(string)
      size = optional(number)
      discard = optional(string)
      file_format = optional(string)
      interface = optional(string)
      datastore_id = optional(string)
    }))
    network = object({
      bridge = optional(string)
      mac_address = optional(string)
      model = optional(string)
      vlan_id = optional(number)
    })
  })
  default = {
    cpu = {
      cores = 1
      hotplugged = 0
    }
    memory = {
      dedicated = 1024
    }
    disk = {
      cache = "none"
      size = 8
      interface = "scsi0"
      datastore_id = "nvme-pool"
    }
    network = {
      bridge = "vmbr1"
    }
  }
}

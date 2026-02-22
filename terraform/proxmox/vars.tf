variable "node" {
  type    = string
  default = "pve-srv-01"
}

variable "domain" {
  type    = string
  default = "chkpwd.com"
}

variable "dns_servers" {
  type    = list(string)
  default = ["1.1.1.1", "1.0.0.1"]
}

variable "timezone" {
  type    = string
  default = "America/New_York"
}

variable "nodes_cfg" {
  type = map(object({
    name   = string
    cpus   = number
    memory = string
    vm_id  = number
  }))
  default = {
    "ai-inference-01" = { vm_id = 505, name = "ai-inference-01", cpus = 4, memory = 1024 * 4 }
    "openshift-tools" = { vm_id = 511, name = "openshift-tools", cpus = 2, memory = 1024 * 4 }
    "mc-kasten-01"    = { vm_id = 514, name = "mc-kasten-01", cpus = 2, memory = 1024 * 8 }
    "mc-kasten-02"    = { vm_id = 515, name = "mc-kasten-02", cpus = 2, memory = 1024 * 8 }
  }
}

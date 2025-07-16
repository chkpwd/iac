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
    "gravity-dns-02"  = { vm_id = 300, name = "gravity-dns-02", cpus = 1, memory = 1024 * 1 }
    "veeam-backup-01" = { vm_id = 510, name = "veeam-backup-01", cpus = 8, memory = 1024 * 2 }
  }
}

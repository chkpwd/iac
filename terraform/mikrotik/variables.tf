variable "enabled_services" {
  type = list(object({
    name = string
    port = number
  }))
  default = [
    { name = "winbox", port = 8291 },
  ]
}

variable "disabled_services" {
  type = list(object({
    name = string
    port = number
  }))
  default = [
    { name = "api", port = 8728 },
    { name = "ftp", port = 21 },
    { name = "telnet", port = 23 },
    { name = "www", port = 80 },
  ]
}

variable "networks" {
  type = map(object({
    vlan_id        = number
    interface      = string
    untagged_ports = optional(list(string), [])
  }))
  default = {
    lan   = { vlan_id = 10, interface = "bridge" }
    iot   = { vlan_id = 20, interface = "iot", untagged_ports = ["ether4"] }
    guest = { vlan_id = 30, interface = "guest" }
  }
}
variable "dns_ip" {
  type    = string
  default = "10.0.10.4"
}

variable "domain" {
  type    = string
  default = "chkpwd.com"
}

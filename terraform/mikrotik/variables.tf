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
    vlan_id   = number
    interface = string
  }))
  default = {
    lan   = { vlan_id = 10, interface = "bridge" }
    iot   = { vlan_id = 20, interface = "iot" }
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

variable "address_list" {
  type = list(object({
    address  = string
    comment  = optional(string)
    disabled = optional(bool, false)
    dynamic  = optional(bool, false)
    list     = string
  }))

  default = [
    { address = "10.0.10.0/24", comment = "LAN", list = "LAN" },
    { address = "10.0.0.0/8", comment = "rfc1918", list = "private_addr" },
    { address = "172.16.0.0/12", comment = "rfc1918", list = "private_addr" },
    { address = "192.168.0.0/16", comment = "rfc1918", list = "private_addr" },
  ]
}

variable "vlans" {
  type = map(string)
  default = {
    "guest"   = "10"
    "iot"   = "20"
  }
  description = "Mapping of vlan IDs"
}

variable "site" {
  default = "default"
}

variable "private_key_path" {
  default = "~/.ssh/unifi"
}

variable "vlans" {
  type = map(string)
  default = {
    "iot"   = "10"
    "lab"   = "20"
  }
  description = "Mapping of vlan IDs"
}

variable "site" {
  default = "default"
}

variable "private_key_path" {
  default = "~/.ssh/unifi"
}

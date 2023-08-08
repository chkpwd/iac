variable "vlans" {
  type = map(string)
  default = {
    "media" = "10"
    "iot"   = "20"
    "lab"   = "30"
  }
  description = "Mapping of vlan IDs"
}

variable "site" {
  default = "default"
}

variable "private_key_path" {
  default = "~/.ssh/unifi"
}
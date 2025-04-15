variable "vlans" {
  type = map(string)
  default = {
    "guest" = "10"
    "iot"   = "20"
  }
  description = "Mapping of vlan IDs"
}

variable "site" {
  type    = string
  default = "default"
}

variable "public_key_path" {
  type    = string
  default = "~/.ssh/unifi.pub"
}

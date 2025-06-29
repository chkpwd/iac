variable "interfaces" {
  type = map(string)
  default = {
    "guest" = "30"
    "iot"   = "20"
    # "lan"   = "10"
  }
  description = "Mapping of interface IDs"
}

variable "site" {
  type    = string
  default = "default"
}

variable "public_key_path" {
  type    = string
  default = "~/.ssh/unifi.pub"
}

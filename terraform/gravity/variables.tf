variable "zone" {
  type    = string
  default = "chkpwd.com."
}

variable "vlan_ids" {
  type = object({
    lan   = number
    iot   = number
    guest = number
  })
  default = {
    lan   = 16
    iot   = 10
    guest = 20
  }
}

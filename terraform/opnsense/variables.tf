variable "vlan_ids" {
  type = object({
    lan   = number
    iot   = number
    guest = number
  })
  default = {
    lan   = 16
    iot   = 20
    guest = 10
  }
}

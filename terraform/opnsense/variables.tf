variable "vlan_ids" {
  type = object({
    iot   = number
    guest = number
    mgmt  = number
  })
  default = {
    guest = 10
    iot   = 20
    mgmt  = 30
  }
}

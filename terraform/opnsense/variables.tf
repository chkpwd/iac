variable "interfaces" {
  type = object({
    iot   = number
    guest = number
    lan   = number
    mgmt  = number
  })
  default = {
    guest = 30
    iot   = 20
    lan   = 10
    mgmt  = 40
  }
}

# Define a map of Vultr instance resources
variable "instances" {
  type = map(object({
    region   = string
    plan     = string
    os_id    = number
    label    = string
    hostname = string
  }))
  default = {
    instances = {
      region   = "ewr"
      plan     = "vc2-1c-0.5gb"
      os_id    = 448 # Rocky Linux 8 x64
      label    = "rockie"
      hostname = "rocky-linux"
    }
  }
}
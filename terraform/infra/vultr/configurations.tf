# Define a map of Vultr instance resources
variable "hattie" {
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
      os_id    = 1929 # Fedora 37 x64
      label    = "hats"
      hostname = "fedora-linux"
    }
  }
}
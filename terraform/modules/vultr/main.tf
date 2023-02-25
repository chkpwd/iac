terraform {
  required_providers {
    vultr = {
      source = "vultr/vultr"
      version = "2.12.0"
    }
  }
}

resource "vultr_instance" "my_instance" {
    plan = "vc2-1c-0.5gb"
    region = "ewr"
    os_id = 448
    label = "rocky-balboa"
    tags = ["rocky-balboa"]
    hostname = "rocky-balboa"
    enable_ipv6 = true
    backups = "disabled"
    ddos_protection = false
    activation_email = false
}
#===============================================================================
# Vultr Resources
#===============================================================================

resource "vultr_instance" "rocks" {

    region   = "ewr"
    plan     = "vc2-1c-0.5gb"
    os_id    = 448 # Rocky Linux 8 x64
    label    = "rockie"
    hostname = "rocky-linux"
    enable_ipv6 = true
    backups = "disabled"
    ddos_protection = false
    activation_email = false
    tags = ["rocks"]
  
}

resource "vultr_instance" "fedora_hats" {
    for_each = var.hattie

    region    = each.value.region
    plan      = each.value.plan
    os_id     = each.value.os_id
    label     = each.value.label
    hostname  = each.value.hostname
    enable_ipv6 = true
    backups = "disabled"
    ddos_protection = false
    activation_email = false
    tags = ["rocks"]
  
}

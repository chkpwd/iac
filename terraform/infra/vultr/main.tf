#===============================================================================
# vSphere Resources
#===============================================================================

resource "vultr_instance" "instances" {
    for_each = var.instances

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
  
  provisioner "remote-exec" {
    
  }
}

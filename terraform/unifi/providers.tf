#===============================================================================
# Vultr Provider
#===============================================================================

terraform {
  required_providers {
    unifi = {
      source = "paultyng/unifi"
      version = "0.41.0"
    }
    sops = { 
      source = "carlpett/sops"
      version = "0.7.2"
    }
  }
}

data "sops_file" "unifi-secrets" {
  source_file = "../terraform.sops.yaml"
}

provider "unifi" {
  username = "terraform"
  password = "Porridge-Overplant2-Flagstone"
  api_url  = "https://unifi-controller.local.chkpwd.com:8443"

  allow_insecure = true

  site = var.site
}
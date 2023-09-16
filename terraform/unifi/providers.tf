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
      version = "1.0.0"
    }
  }
}

data "sops_file" "unifi-secrets" {
  source_file = "../terraform.sops.yaml"
}

provider "unifi" {
  username = "terraform"
  password = data.sops_file.unifi-secrets.data["tf_svc_unifi_pwd"]
  api_url  = "http://172.16.16.205:8443"

  allow_insecure = true

  site = var.site
}
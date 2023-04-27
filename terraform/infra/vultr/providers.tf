#===============================================================================
# vSphere Provider
#===============================================================================

terraform {
  required_providers {
    vultr = {
      source = "vultr/vultr"
      version = "2.12.0"
    }
    sops = { 
      source = "carlpett/sops"
      version = "0.7.2"
    }
  }
}

data "sops_file" "vsphere-secrets" {
  source_file = "../../terraform.sops.yml"
}

# Configure the Vultr Provider
provider "vultr" {
  api_key = "${data.sops_file.vsphere-secrets.data["vultr_api_key"]}"
  rate_limit = 100
  retry_limit = 3
}
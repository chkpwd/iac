#===============================================================================
# vSphere Provider
#===============================================================================

terraform {
  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 3.0"
    }
    sops = { 
      source = "carlpett/sops"
      version = "0.7.2"
    }
  }
}

data "sops_file" "vsphere-secrets" {
  source_file = "../terraform.sops.yaml"
}

provider "cloudflare" {
  api_token = var.cloudflare_api_token
}
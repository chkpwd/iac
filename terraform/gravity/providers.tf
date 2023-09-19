terraform {
  required_providers {
    opnsense = {
      source  = "BeryJu/gravity"
      version = "0.3.0"
    }
    sops = {
      source  = "carlpett/sops"
      version = "1.0.0"
    }
  }
}

data "sops_file" "opnsense-secrets" {
  source_file = "../terraform.sops.yaml"
}

provider "gravity" {
  url        = data.sops_file.gravity-secrets.data["gravity_url"]
  token      = data.sops_file.gravity-secrets.data["gravity_token"]
  insecure   = false
}
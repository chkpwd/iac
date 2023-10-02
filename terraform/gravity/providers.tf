terraform {
  required_providers {
    gravity = {
      source  = "BeryJu/gravity"
      version = "0.3.1"
    }
    sops = {
      source  = "carlpett/sops"
      version = "1.0.0"
    }
  }
}

data "sops_file" "gravity-secrets" {
  source_file = "../terraform.sops.yaml"
}

provider "gravity" {
  url        = "http://172.16.16.4:8008" #TODO Maybe cycle through an array of nodes
  token      = data.sops_file.gravity-secrets.data["gravity_token"]
  insecure   = false
}
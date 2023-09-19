#===============================================================================
# vSphere Provider
#===============================================================================

terraform {
  required_providers {
    adguard = {
      source = "gmichels/adguard"
      version = "0.7.2"
    }
    sops = { 
      source = "carlpett/sops"
      version = "1.0.0"
    }
  }
}

data "sops_file" "adguard-home-secrets" {
  source_file = "../terraform.sops.yaml"
}

# configuration for adguard home
provider "adguard" {
  host     = "172.16.16.1:8080"
  username = "admin"
  password = "${data.sops_file.adguard-home-secrets.data["adguard_home_password"]}"
  scheme   = "http" # defaults to https
  timeout  = 5
}
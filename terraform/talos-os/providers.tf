# see https://github.com/hashicorp/terraform
terraform {
  required_providers {
    random = {
      source  = "hashicorp/random"
      version = "3.5.1"
    }
    template = {
      source  = "hashicorp/template"
      version = "2.2.0"
    }
    vsphere = {
      source  = "hashicorp/vsphere"
      version = "2.3.1"
    }
    talos = {
      source  = "siderolabs/talos"
      version = "0.3.0"
    }
    sops = {
      source  = "carlpett/sops"
      version = "0.7.2"
    }
  }
}

data "sops_file" "talos-secrets" {
  source_file = "../terraform.sops.yaml"
}

provider "talos" {}

# Configure the vSphere Provider
provider "vsphere" {
  vsphere_server = var.vsphere_server
  user = data.sops_file.talos-secrets.data["vsphere_user"]
  password = data.sops_file.talos-secrets.data["vsphere_password"]

  allow_unverified_ssl = var.vsphere_unverified_ssl
}
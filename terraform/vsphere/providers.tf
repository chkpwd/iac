terraform {
  required_providers {
    vsphere = {
      source = "hashicorp/vsphere"
      version = "2.7.0"
    }
    sops = { 
      source = "carlpett/sops"
      version = "1.0.0"
    }
  }
}

data "sops_file" "vsphere-secrets" {
  source_file = "../terraform.sops.yaml"
}

# Configure the vSphere Provider
provider "vsphere" {
  vsphere_server = "vcenter.${var.domain}"
  user = "${data.sops_file.vsphere-secrets.data["vsphere_user"]}"
  password = "${data.sops_file.vsphere-secrets.data["vsphere_password"]}"

  allow_unverified_ssl = "${var.vsphere_unverified_ssl}"
}

terraform {
  required_providers {
    oci = {
      source = "oracle/oci"
      version = "5.11.0"
    }
    sops = { 
      source = "carlpett/sops"
      version = "0.7.2"
    }
  }
}

data "sops_file" "oci-secrets" {
  source_file = "../terraform.sops.yaml"
}

provider "oci" {
  tenancy_ocid = "${data.sops_file.oci-secrets.data["oci_tenancy_ocid"]}"
  user_ocid = "${data.sops_file.oci-secrets.data["user_oci"]}"
  fingerprint = "${data.sops_file.oci-secrets.data["oci_fingerprint"]}"
  private_key_path = var.private_key_path
  region = "us-ashburn-1"
}
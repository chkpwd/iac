terraform {
  required_providers {
    oci = {
      source = "oracle/oci"
      version = "5.23.0"
    }
    sops = { 
      source = "carlpett/sops"
      version = "1.0.0"
    }
  }
}
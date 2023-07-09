terraform {
  required_providers {
    oci = {
      source = "oracle/oci"
      version = "5.3.0"
    }
    sops = { 
      source = "carlpett/sops"
      version = "0.7.2"
    }
  }
}
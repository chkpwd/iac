terraform {
  required_version = "1.11.3"
  required_providers {
    proxmox = {
      source  = "bpg/proxmox"
      version = "0.74.1"
    }
    random = {
      source  = "hashicorp/random"
      version = "3.7.1"
    }
  }
}

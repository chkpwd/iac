terraform {
  required_version = "1.11.4"
  required_providers {
    proxmox = {
      source  = "bpg/proxmox"
      version = "0.76.1"
    }
    random = {
      source  = "hashicorp/random"
      version = "3.7.2"
    }
  }
}

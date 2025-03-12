terraform {
  required_version = "1.11.2"
  required_providers {
    proxmox = {
      source  = "bpg/proxmox"
      version = "0.73.1"
    }
    random = {
      source  = "hashicorp/random"
      version = "3.7.1"
    }
  }
}

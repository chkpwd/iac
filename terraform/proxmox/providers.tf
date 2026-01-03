terraform {
  required_version = "~> 1.12"
  required_providers {
    proxmox = {
      source  = "bpg/proxmox"
      version = "0.91.0"
    }
    external = {
      source  = "hashicorp/external"
      version = "~> 2"
    }
    macaddress = {
      source  = "ivoronin/macaddress"
      version = "~> 0.3"
    }
  }
}

provider "proxmox" {
  endpoint  = "https://10.0.10.3:8006"
  api_token = "terraform@pve!provider=c20f2dc8-2db4-4399-b3b4-e5445850bf2a"
  insecure  = true
  tmp_dir   = "/var/tmp"

  ssh {
    agent       = false
    username    = "root"
    private_key = file("~/.ssh/main")
  }
}

terraform {
  required_providers {
    proxmox = {
      source = "bpg/proxmox"
      version = "0.48.1"
    }
  }
}

provider "proxmox" {
  endpoint = "https://pve1.local.chkpwd.com:8006"
  api_token = "terraform@pve!provider=c20f2dc8-2db4-4399-b3b4-e5445850bf2a"
  insecure = true
  tmp_dir  = "/var/tmp"

  ssh {
    agent = true
    username = "terraform"
  }
}

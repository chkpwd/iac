terraform {
  required_version = "~> 1.12"

  required_providers {
    routeros = {
      source  = "terraform-routeros/routeros"
      version = "~> 1"
    }
    external = {
      source  = "hashicorp/external"
      version = "~> 2"
    }
  }

  backend "remote" {
    hostname     = "app.terraform.io"
    organization = "chkpwd"

    workspaces {
      name = "mikrotik"
    }
  }
}

data "external" "bws_lookup" {
  program = ["python3", "../bws_lookup.py"]
  query = {
    key = "infra-network-secrets,cloudflare-dns-secrets,mikrotik-ddns"
  }
}

provider "routeros" {
  hosturl  = "https://10.0.10.1"
  username = "admin"
  password = data.external.bws_lookup.result["infra-network-secrets_mikrotik_password"]
  insecure = true
}

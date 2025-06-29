terraform {
  required_version = "~> 1.12"
  required_providers {
    gravity = {
      source  = "BeryJu/gravity"
      version = "0.3.7"
    }
    external = {
      source  = "hashicorp/external"
      version = "~> 2"
    }
  }
}

data "external" "bws_lookup" {
  program = ["python3", "../bws_lookup.py"]
  query = {
    key = "infra-gravity-secrets"
  }
}

provider "gravity" {
  url      = "http://mgmt-srv-01.chkpwd.com:8008"
  token    = data.external.bws_lookup.result["infra-gravity-secrets_admin_token"]
  insecure = false
}

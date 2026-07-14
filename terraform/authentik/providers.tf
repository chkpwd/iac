terraform {
  required_version = "~> 1.12"
  required_providers {
    authentik = {
      source  = "goauthentik/authentik"
      version = "2026.5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "3.9.0"
    }
    external = {
      source  = "hashicorp/external"
      version = "~> 2"
    }
  }
}

locals {
  bws_keys = [
    "authentik",
    "miniflux",
    "karakeep",
    "grimmory",
    "trek",
    "sure",
    "immich",
  ]
}

data "external" "bws_lookup" {
  program = ["python3", "../bws_lookup.py"]
  query = {
    keys = jsonencode(local.bws_keys)
  }
}

provider "authentik" {
  url   = "https://authentik.chkpwd.com"
  token = data.external.bws_lookup.result["authentik_bootstrap_token"]
}

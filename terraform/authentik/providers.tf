terraform {
  required_version = "~> 1.12"
  required_providers {
    authentik = {
      source  = "goauthentik/authentik"
      version = "2025.12.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "3.7.2"
    }
    external = {
      source  = "hashicorp/external"
      version = "~> 2"
    }
  }
}

data "external" "bws_lookup" {
  program = ["python3", "../bws_lookup.py"]
  query = { # TODO: need to revisit this and find a cleaner approach
    key = "ns-security-authentik,infra-media-secrets,ns-tools-miniflux,ns-tools-karakeep,booklore,mediamanager"
    # authentik = "ns-security-authentik_bootstrap_token"
  }
}

provider "authentik" {
  url   = "https://authentik.chkpwd.com"
  token = data.external.bws_lookup.result["ns-security-authentik_bootstrap_token"]
}

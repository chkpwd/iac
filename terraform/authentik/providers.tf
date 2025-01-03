terraform {
  required_providers {
    authentik = {
      source  = "goauthentik/authentik"
      version = "2024.12.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "3.6.3"
    }
  }
}

data "external" "bws_lookup" {
  program = ["python3", "../bws_lookup.py"]
  query = {
    key = "ns-security-authentik,ns-tools-miniflux,infra-media-secrets,ns-tools-miniflux,ns-tools-immich,infra-semaphore-secrets"
    authentik = "ns-security-authentik_bootstrap_token"
  }
}

provider "authentik" {
  url   = "https://authentik.chkpwd.com"
  token = data.external.bws_lookup.result["ns-security-authentik_bootstrap_token"]
}

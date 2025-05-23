terraform {
  required_version = "1.12.1"
  required_providers {
    authentik = {
      source  = "goauthentik/authentik"
      version = "2025.4.0"
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
  query = {
    key       = "ns-security-authentik,ns-tools-miniflux,infra-media-secrets,ns-tools-miniflux,ns-tools-immich,infra-semaphore-secrets,ns-tools-karakeep"
    authentik = "ns-security-authentik_bootstrap_token"
  }
}

provider "authentik" {
  url   = "https://authentik.chkpwd.com"
  token = data.external.bws_lookup.result["ns-security-authentik_bootstrap_token"]
}

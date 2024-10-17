terraform {
  required_providers {
    sonarr = {
      source  = "devopsarr/sonarr"
      version = "3.2.0"
    }
    prowlarr = {
      source  = "devopsarr/prowlarr"
      version = "2.4.3"
    }
    radarr = {
      source  = "devopsarr/radarr"
      version = "2.3.0"
    }
  }
}

data "external" "bws_lookup" {
  program = ["python3", "../bws_lookup.py"]
  query = {
    key = "infra-media-secrets"
  }
}


provider "sonarr" {
  url     = "https://sonarr.${var.local_domain}"
  api_key = data.external.bws_lookup.result["infra-media-secrets_sonarr_api_key"]
}

provider "radarr" {
  url     = "https://radarr.${var.local_domain}"
  api_key = data.external.bws_lookup.result["infra-media-secrets_radarr_api_key"]
}

provider "prowlarr" {
  url     = "https://prowlarr.${var.local_domain}"
  api_key = data.external.bws_lookup.result["infra-media-secrets_prowlarr_api_key"]
}

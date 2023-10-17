terraform {
  required_providers {
    sonarr = {
      source = "devopsarr/sonarr"
      version = "3.1.0"
    }
    prowlarr = {
      source = "devopsarr/prowlarr"
      version = "2.1.0"
    }
    radarr = {
      source = "devopsarr/radarr"
      version = "2.0.1"
    }
    sops = { 
      source = "carlpett/sops"
      version = "1.0.0"
    }
  }
}

data "sops_file" "servarr-secrets" {
  source_file = "../terraform.sops.yaml"
}

provider "sonarr" {
  url     = "http://sonarr.${var.local_domain}"
  api_key = "${data.sops_file.servarr-secrets.data["sonarr_api_key"]}"
}

provider "radarr" {
  url     = "http://radarr.${var.local_domain}"
  api_key = "${data.sops_file.servarr-secrets.data["radarr_api_key"]}"
}

provider "prowlarr" {
  url     = "http://prowlarr.${var.local_domain}"
  api_key = "${data.sops_file.servarr-secrets.data["prowlarr_api_key"]}"
}
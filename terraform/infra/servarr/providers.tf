terraform {
  required_providers {
    sonarr = {
      source = "devopsarr/sonarr"
      version = "3.0.0"
    }
    prowlarr = {
      source = "devopsarr/prowlarr"
      version = "2.0.0"
    }
    radarr = {
      source = "devopsarr/radarr"
      version = "1.8.0"
    }
    sops = { 
      source = "carlpett/sops"
      version = "0.7.2"
    }
  }
}

data "sops_file" "servarr-secrets" {
  source_file = "../../terraform.sops.yaml"
}

provider "sonarr" {
  url     = "http://${media_host_ip}:${sonarr_port}"
  api_key = "${data.sops_file.servarr-secrets.data["sonarr_api_key"]}"
}

provider "radarr" {
  url     = "http://${media_host_ip}:${radarr_port}"
  api_key = "${data.sops_file.servarr-secrets.data["radarr_api_key"]}"
}

provider "prowlarr" {
  url     = "http://${media_host_ip}:${prowlarr_port}"
  api_key = "${data.sops_file.servarr-secrets.data["prowlarr_api_key"]}"
}
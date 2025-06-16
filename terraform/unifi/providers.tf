terraform {
  required_version = "~> 1.12"
  required_providers {
    unifi = {
      source  = "paultyng/unifi"
      version = "0.41.0"
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
    key = "infra-network-secrets"
  }
}

provider "unifi" {
  username = "terraform"
  password = data.external.bws_lookup.result["infra-network-secrets_tf_svc_unifi_pwd"]
  api_url  = "https://172.16.16.33:8443"

  allow_insecure = true

  site = var.site
}

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

locals {
  bws_keys = [
    "infra-network-secrets",
  ]
}

data "external" "bws_lookup" {
  program = ["python3", "../bws_lookup.py"]
  query = {
    keys = jsonencode(local.bws_keys)
  }
}

provider "unifi" {
  username = "terraform"
  password = data.external.bws_lookup.result["infra-network-secrets_tf_svc_unifi_pwd"]
  api_url  = "https://10.0.10.33:8443"

  allow_insecure = true

  site = var.site
}

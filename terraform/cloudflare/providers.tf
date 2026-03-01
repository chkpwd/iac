terraform {
  required_version = "~> 1.12"
  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "5.18.0"
    }
    tfe = {
      source  = "hashicorp/tfe"
      version = "~> 0.74.0"
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
    key = "common-secrets,infra-network-secrets,cloud-aws-proxy-secrets,cloudflare-dns-secrets,cloud-github-secrets,monitoring"
  }
}

provider "cloudflare" {
  api_token = data.external.bws_lookup.result["cloudflare-dns-secrets_zone_token"]
}

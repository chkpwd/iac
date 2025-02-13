#===============================================================================
# Cloudflare Provider
#===============================================================================

terraform {
  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "5.1.0"
    }
    tfe = {
      source  = "hashicorp/tfe"
      version = "~> 0.63.0"
    }
  }
}

data "external" "bws_lookup" {
  program = ["python3", "../bws_lookup.py"]
  query = {
    key = "common-secrets,infra-network-secrets,cloud-aws-proxy-secrets,cloudflare-dns-secrets,cloud-github-secrets"
  }
}

provider "cloudflare" {
  api_token = data.external.bws_lookup.result["cloudflare-dns-secrets_zone_token"]
}

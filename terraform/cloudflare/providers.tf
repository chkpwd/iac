#===============================================================================
# Cloudflare Provider
#===============================================================================

terraform {
  required_version = "1.11.1"
  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "5.2.0"
    }
    tfe = {
      source  = "hashicorp/tfe"
      version = "~> 0.64.0"
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
    key = "common-secrets,infra-network-secrets,cloud-aws-proxy-secrets,cloudflare-dns-secrets,cloud-github-secrets,tig-info"
  }
}

provider "cloudflare" {
  api_token = data.external.bws_lookup.result["cloudflare-dns-secrets_zone_token"]
}

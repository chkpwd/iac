#===============================================================================
# Cloudflare Provider
#===============================================================================

terraform {
  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 4.0"
    }
    sops = {
      source  = "carlpett/sops"
      version = "1.0.0"
    }
    tfe = {
      source = "hashicorp/tfe"
      version = "~> 0.56.0"
    }
  }
}

data "external" "bws_lookup" {
  program = ["python3","../bws_lookup.py"]
  query = {
    key = "common-secrets,infra-network-secrets,cloud-aws-proxy-secrets,cloudflare-dns-secrets"
  }
}

data "sops_file" "cloudflare-secrets" {
  source_file = "../terraform.sops.yaml"
}

provider "cloudflare" {
  api_token = data.external.bws_lookup.result["cloudflare-dns-secrets_zone_token"]
}

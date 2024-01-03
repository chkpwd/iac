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
      version = "~> 0.51.0"
    }
  }
}

data "sops_file" "cloudflare-secrets" {
  source_file = "../terraform.sops.yaml"
}

provider "cloudflare" {
  api_token = data.sops_file.cloudflare-secrets.data["cloudflare_zone_token"]
}

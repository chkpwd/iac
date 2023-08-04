#===============================================================================
# Fluxcd Provider
#===============================================================================

terraform {
  required_providers {
    flux = {
      source = "fluxcd/flux"
      version = "1.0.0-rc.5"
    }
    sops = { 
      source = "carlpett/sops"
      version = "0.7.2"
    }
    github = {
      source  = "integrations/github"
      version = ">= 5.24.0"
    }
  }
}

data "sops_file" "fluxcd-secrets" {
  source_file = "../terraform.sops.yaml"
}

locals {
  github_org        = "chkpwd"
  github_repository = "iac"
}

provider "flux" {
  kubernetes = {
    config_path = "~/.kube/config"
  }
  git = {
    url = "ssh://git@github.com/${local.github_org}/${local.github_repository}.git"
    ssh = {
      username    = "git"
      private_key = tls_private_key.flux_secret.private_key_pem
    }
  }
}

provider "github" {
  owner = "chkpwd"
  token = "${data.sops_file.fluxcd-secrets.data["github_token"]}"
}
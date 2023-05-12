#===============================================================================
# vSphere Provider
#===============================================================================

terraform {
  required_providers {
    flux = {
      source = "fluxcd/flux"
      version = "1.0.0-rc.1"
    }
    sops = { 
      source = "carlpett/sops"
      version = "0.7.2"
    }
    github = {
      source  = "integrations/github"
      version = ">=5.24.0"
    }
  }
}

data "sops_file" "fluxcd-secrets" {
  source_file = "../../terraform.sops.yaml"
}

locals {
  github_org        = "chkpwd"
  github_repository = "boilerplates"
}

provider "flux" {
  kubernetes = {
    config_path = "~/.kube/config"
  }
  git = {
    url = "https://github.com/${local.github_org}/${local.github_repository}.git"
    http = {
      username = "unixchkpwd"
      password = "${data.sops_file.fluxcd-secrets.data["github_token"]}"
    }
  }
}

#===============================================================================
# vSphere Provider
#===============================================================================

terraform {
  required_providers {
    vultr = {
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

# Configure the fluxcd Provider
provider "flux" {
  kubernetes = {
    config_path = "~/.kube/config"
  }
  provider "github" {
    owner = var.github_org
    token = "${data.sops_file.fluxcd_secrets.data["github_token"]}"
  }
    
}
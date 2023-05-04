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
  }
}

data "sops_file" "fluxcd-secrets" {
  source_file = "../../terraform.sops.yml"
}

# Configure the fluxcd Provider
provider "flux" {
  kubernetes = {
    config_path = "~/.kube/config"
  }
  git = {
    url = "https://github.com/chkpwd/boilerplates.git"
    
    
  }
}
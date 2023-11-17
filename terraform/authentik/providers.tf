terraform {
  required_providers {
    authentik = {
      source = "goauthentik/authentik"
      version = "2023.10.0"
    }
    sops = { 
      source = "carlpett/sops"
      version = "1.0.0"
    }
  }
}

data "sops_file" "authentik-secrets" {
  source_file = "../terraform.sops.yaml"
}

provider "authentik" {
  url   = "https://authentik.chkpwd.com"
  token = data.sops_file.authentik-secrets.data["authentik_token"]
}

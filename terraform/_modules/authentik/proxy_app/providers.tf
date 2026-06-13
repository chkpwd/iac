terraform {
  required_version = "~> 1.12"
  required_providers {
    authentik = {
      source  = "goauthentik/authentik"
      version = "~> 2026.5.0"
    }
  }
}

terraform {
  required_version = "1.11.0"
  required_providers {
    authentik = {
      source  = "goauthentik/authentik"
      version = "~> 2024.12.1"
    }
  }
}

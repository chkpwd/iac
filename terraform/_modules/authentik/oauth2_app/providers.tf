terraform {
  required_version = "1.12.1"
  required_providers {
    authentik = {
      source  = "goauthentik/authentik"
      version = "~> 2025.4.0"
    }
  }
}

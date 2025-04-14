terraform {
  required_version = "1.11.4"
  required_providers {
    authentik = {
      source  = "goauthentik/authentik"
      version = "~> 2025.2.0"
    }
  }
}

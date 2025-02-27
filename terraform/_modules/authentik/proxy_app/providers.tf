terraform {
  required_version = "1.9.8"
  required_providers {
    authentik = {
      source = "goauthentik/authentik"
      version = "~> 2024.12.1"
    }
  }
}

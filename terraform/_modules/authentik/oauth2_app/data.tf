data "authentik_flow" "default-authorization-flow" {
  slug = "default-provider-authorization-implicit-consent"
}

data "authentik_flow" "default-source-authentication" {
  slug = "default-source-authentication"
}

data "authentik_flow" "default-source-enrollment" {
  slug = "default-source-enrollment"
}

data "authentik_certificate_key_pair" "generated" {
  name = "authentik Self-signed Certificate"
}

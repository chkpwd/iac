data "authentik_flow" "default-source-authentication" {
  slug = "default-source-authentication"
}

data "authentik_flow" "default-source-enrollment" {
  slug = "default-source-enrollment"
}

data "authentik_flow" "default-authorization-flow" {
  slug = "default-provider-authorization-implicit-consent"
}

data "authentik_flow" "default-authentication-flow" {
  slug = "default-authentication-flow"
}

data "authentik_certificate_key_pair" "generated" {
  name = "authentik Self-signed Certificate"
}

data "authentik_property_mapping_provider_scope" "sources" {
  managed_list = [
    "goauthentik.io/providers/oauth2/scope-email",
    "goauthentik.io/providers/oauth2/scope-openid",
    "goauthentik.io/providers/oauth2/scope-profile"
  ]
}

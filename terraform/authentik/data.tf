data "authentik_flow" "default-source-authentication" {
  slug = "default-source-authentication"
}

data "authentik_property_mapping_provider_scope" "sources" {
  managed_list = [
    "goauthentik.io/providers/oauth2/scope-email",
    "goauthentik.io/providers/oauth2/scope-openid",
    "goauthentik.io/providers/oauth2/scope-profile"
  ]
}

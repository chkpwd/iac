resource "authentik_provider_oauth2" "oauth2" {
  name                  = "${lower(var.name)}"
  client_id             = var.oauth2_values.client_id
  client_secret         = var.oauth2_values.client_secret
  authentication_flow   = data.authentik_flow.default-source-authentication.id
  authorization_flow    = data.authentik_flow.default-authorization-flow.id
  access_token_validity = "minutes=10"
  property_mappings     = var.oauth2_values.property_mappings
  signing_key           = data.authentik_certificate_key_pair.generated.id
  lifecycle {
    ignore_changes      = [client_secret]
  }
}

resource "authentik_application" "app" {
  name              = var.name
  slug              = replace(lower(var.name), " ", "-")
  protocol_provider = authentik_provider_oauth2.oauth2.id
  meta_icon         = var.app_values.icon_url
  meta_publisher    = var.app_values.meta_publisher
  meta_description  = var.app_values.meta_description
  group             = var.group
}

resource "authentik_policy_binding" "app-access" {
  for_each = toset(var.access_group)
  target   = authentik_application.app.uuid
  group    = each.key
  order    = index(var.access_group, each.key) + 100
}

resource "authentik_source_oauth" "main" {
  name                         = "${lower(var.name)}"
  slug                         = replace(lower(var.name), " ", "-")
  authentication_flow          = data.authentik_flow.default-source-authentication.id
  enrollment_flow              = data.authentik_flow.default-source-enrollment.id
  provider_type                = var.provider_type
  consumer_key                 = var.consumer_key
  consumer_secret              = var.consumer_secret
  lifecycle {
    ignore_changes = [consumer_key, consumer_secret, access_token_url, authorization_url, profile_url]
  }
}

resource "authentik_application" "app" {
  name              = var.name
  slug              = replace(lower(var.name), " ", "-")
  protocol_provider = authentik_source_oauth.main.id
  meta_icon         = var.icon_url
  meta_publisher    = var.meta_publisher
  group             = var.group
}

resource "authentik_policy_binding" "app-access" {
  for_each = toset(var.access_group)
  target   = authentik_application.app.uuid
  group    = each.key
  order    = index(var.access_group, each.key) + 100
}

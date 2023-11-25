resource "authentik_provider_proxy" "provider" {
  name                         = "${lower(var.name)}"
  internal_host                = var.proxy_values.internal
  external_host                = var.proxy_values.external
  mode                         = var.proxy_values.internal == "" ? "forward_single" : "proxy" # Can't be empty
  authorization_flow           = data.authentik_flow.default-authorization-flow.id
  skip_path_regex              = var.proxy_values.skip_path_regex
  internal_host_ssl_validation = var.proxy_values.internal_host_ssl_validation
  jwks_sources                 = var.proxy_values.jwks_sources
  access_token_validity        = "hours=8"
  lifecycle {
    ignore_changes = [ jwks_sources ]
  }
}

resource "authentik_application" "app" {
  name              = var.name
  slug              = replace(lower(var.name), " ", "-")
  protocol_provider = authentik_provider_proxy.provider.id
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

resource "authentik_application" "app" {
  name              = var.name
  slug              = replace(lower(var.name), " ", "-")
  protocol_provider = authentik_provider_ldap.main.id
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

resource "authentik_service_connection_kubernetes" "main" {
  name  = "Local Kubernetes Cluster"
  local = true
}

resource "authentik_outpost" "main" {
  name = "authentik Embedded Outpost"
  protocol_providers = [
    module.authentik-app-sonarr.provider_id,
    module.authentik-app-radarr.provider_id,
    module.authentik-app-prowlarr.provider_id,
    module.authentik-app-sabnzbd.provider_id,
    module.authentik-app-mainsail.provider_id,
    module.authentik-app-jellyfin.provider_id,
    module.authentik-app-maintainerr.provider_id,
    module.authentik-app-runwhen-local.provider_id,
    module.authentik-app-bazarr.provider_id,
    module.authentik-app-qbittorrent.provider_id,
  ]
  service_connection = authentik_service_connection_kubernetes.main.id
}

resource "authentik_provider_ldap" "main" {
  name        = "authentik LDAP Provider"
  bind_mode   = "direct"
  base_dn     = "dc=ldap,dc=goauthentik,dc=io"
  bind_flow   = data.authentik_flow.default-authentication-flow.id
  search_group = authentik_group.main.id
  mfa_support = "true"
}

resource "authentik_source_plex" "main" {
  enabled             = true
  name                = "plex"
  slug                = "plex"
  authentication_flow = data.authentik_flow.default-authorization-flow.id
  enrollment_flow     = data.authentik_flow.default-authorization-flow.id
  client_id           = data.sops_file.authentik-secrets.data["main_plex_client_id"]
  plex_token          = data.sops_file.authentik-secrets.data["main_plex_token"]
  allow_friends       = true
}

resource "authentik_service_connection_kubernetes" "main" {
  name  = "Local Kubernetes Cluster"
  local = true
}

resource "authentik_outpost" "main" {
  name = "authentik Embedded Outpost"
  protocol_providers = [
    module.authentik-app-podinfo.provider_id,
    module.authentik-app-sonarr.provider_id,
    module.authentik-app-radarr.provider_id,
    module.authentik-app-prowlarr.provider_id,
    module.authentik-app-sabnzbd.provider_id,
  ]
  service_connection = authentik_service_connection_kubernetes.main.id
}

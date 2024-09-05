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
    module.authentik-app-jellyfin.provider_id,
    module.authentik-app-bazarr.provider_id,
    module.authentik-app-qbittorrent.provider_id,
    module.authentik-app-maintainerr.provider_id,
  ]
  config = jsonencode({
    "log_level"                      = "info"
    "authentik_host"                 = "https://authentik.chkpwd.com"
    "authentik_host_insecure"        = false
    "object_naming_template"         = "ak-outpost-%(name)s"
    "kubernetes_replicas"            = 1
    "kubernetes_namespace"           = "security"
    "kubernetes_ingress_annotations" = { "external-dns.alpha.kubernetes.io/exclude" = "true" }
    "kubernetes_service_type"        = "ClusterIP"
    "kubernetes_disabled_components" = ["traefix middleware"]
    "kubernetes_ingress_class_name"  = "int-ingress"
  })
  service_connection = authentik_service_connection_kubernetes.main.id
}

resource "authentik_outpost" "secondary" {
  name = "authentik External Ingress Outpost"
  type = "proxy"
  protocol_providers = [
    module.authentik-app-stirling-pdf.provider_id,
    module.authentik-app-semaphore-ui.provider_id,
  ]
  config = jsonencode({
    "log_level"                      = "info"
    "authentik_host"                 = "https://authentik.chkpwd.com"
    "authentik_host_insecure"        = false
    "object_naming_template"         = "ak-outpost-%(name)s"
    "kubernetes_replicas"            = 1
    "kubernetes_namespace"           = "security"
    "kubernetes_ingress_annotations" = { "external-dns.alpha.kubernetes.io/exclude" = "true" }
    "kubernetes_ingress_secret_name" = "authentik-ext-ingress-outpost-tls"
    "kubernetes_service_type"        = "ClusterIP"
    "kubernetes_disabled_components" = ["traefix middleware"]
    "kubernetes_ingress_class_name"  = "ext-ingress"
  })
  service_connection = authentik_service_connection_kubernetes.main.id
}

resource "authentik_provider_ldap" "main" {
  name      = "authentik LDAP Provider"
  bind_mode = "direct"
  base_dn   = "dc=ldap,dc=goauthentik,dc=io"
  bind_flow = data.authentik_flow.default-authentication-flow.id
  #search_group = authentik_group.main.id #  FIX: (2024-09-04) Chkpwd => deprecated
  mfa_support = "true"
}

resource "authentik_source_plex" "main" {
  enabled             = true
  name                = "plex"
  slug                = "plex"
  authentication_flow = data.authentik_flow.default-source-authentication.id
  client_id           = data.external.bws_lookup.result["infra-media-secrets_main_plex_client_id"]
  plex_token          = data.external.bws_lookup.result["infra-media-secrets_main_plex_token"]
  allow_friends       = true
}

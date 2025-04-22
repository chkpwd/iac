resource "authentik_service_connection_kubernetes" "main" {
  name  = "Local Kubernetes Cluster"
  local = true
}

# resource "authentik_outpost" "main" {
#   name = "authentik Main Outpost"
#   protocol_providers = []
#   config = jsonencode({
#     "log_level"               = "info"
#     "authentik_host"          = "https://authentik.chkpwd.com"
#     "authentik_host_insecure" = false
#     "object_naming_template"  = "ak-outpost-%(name)s"
#     "kubernetes_replicas"     = 1
#     "kubernetes_namespace"    = "security"
#     "kubernetes_ingress_annotations" = {
#       "external-dns.alpha.kubernetes.io/exclude" = "true"
#       "cert-manager.io/cluster-issuer"           = "main-issuer"
#     }
#     "kubernetes_service_type"        = "ClusterIP"
#     "kubernetes_disabled_components" = ["traefik middleware"]
#     "kubernetes_ingress_class_name"  = "int-ingress"
#   })
#   service_connection = authentik_service_connection_kubernetes.main.id
# }

resource "authentik_source_plex" "main" {
  enabled             = true
  name                = "plex"
  slug                = "plex"
  authentication_flow = data.authentik_flow.default-source-authentication.id
  client_id           = data.external.bws_lookup.result["infra-media-secrets_plex_client_id"]
  plex_token          = data.external.bws_lookup.result["infra-media-secrets_plex_token"]
  allow_friends       = true
}

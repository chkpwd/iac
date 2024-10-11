resource "prowlarr_application_sonarr" "sonarr" {
  name                  = "sonarr"
  sync_level            = "fullSync"
  base_url              = "http://sonarr.${var.cluster_media_domain}:${var.ports["sonarr"]}"
  prowlarr_url          = "http://prowlarr.${var.cluster_media_domain}:${var.ports["prowlarr"]}"
  api_key               = data.external.bws_lookup.result["infra-media-secrets_sonarr_api_key"]
  sync_categories       = [5000, 5010, 5030]
  anime_sync_categories = [5070]
}

resource "prowlarr_application_radarr" "radarr" {
  name            = "radarr"
  sync_level      = "fullSync"
  base_url        = "http://radarr.${var.cluster_media_domain}:${var.ports["radarr"]}"
  prowlarr_url    = "http://prowlarr.${var.cluster_media_domain}:${var.ports["prowlarr"]}"
  api_key         = data.external.bws_lookup.result["infra-media-secrets_radarr_api_key"]
  sync_categories = [2000, 2010, 2030]
}

resource "prowlarr_download_client_sabnzbd" "sabnzbd" {
  enable   = true
  priority = 1
  name     = "sabnzbd"
  host     = "sabnzbd.${var.cluster_media_domain}"
  url_base = "/"
  port     = var.ports["sabnzbd"]
  category = "prowlarr"
  api_key  = data.external.bws_lookup.result["infra-media-secrets_sabnzbd_api_key"]
  username = data.external.bws_lookup.result["infra-media-secrets_servarr_username"]
  password = data.external.bws_lookup.result["infra-media-secrets_servarr_password"]
}

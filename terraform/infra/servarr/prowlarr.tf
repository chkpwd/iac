resource "prowlarr_application_sonarr" "sonarr" {
  name                  = "sonarr"
  sync_level            = "fullSync"
  base_url              = "http://${var.media_host_ip}:${var.ports["sonarr"]}"
  prowlarr_url          = "http://${var.media_host_ip}:${var.ports["prowlarr"]}"
  api_key               = "${data.sops_file.servarr-secrets.data["sonarr_api_key"]}"
  sync_categories       = [5000, 5010, 5030]
  anime_sync_categories = [5070]
}

resource "prowlarr_application_radarr" "radarr" {
  name            = "radarr"
  sync_level      = "fullSync"
  base_url        = "http://${var.media_host_ip}:${var.ports["radarr"]}"
  prowlarr_url    = "http://${var.media_host_ip}:${var.ports["prowlarr"]}"
  api_key         = "${data.sops_file.servarr-secrets.data["radarr_api_key"]}"
  sync_categories = [2000, 2010, 2030]
}

resource "prowlarr_download_client_sabnzbd" "sabnzbd" {
  enable   = true
  priority = 1
  name     = "sabnzbd"
  host     = var.media_host_ip
  url_base = "/"
  port     = var.ports["sabnzbd"]
  category = "prowlarr"
  api_key  = "${data.sops_file.servarr-secrets.data["sabnzbd_api_key"]}"
  username = "${data.sops_file.servarr-secrets.data["servarr_username"]}"
  password = "${data.sops_file.servarr-secrets.data["servarr_password"]}"
}

resource "prowlarr_download_client_qbittorrent" "qbiittorrent" {
  enable   = true
  priority = 2
  name     = "qbittorrent"
  host     = var.media_host_ip
  url_base = "/"
  port     = var.ports["qbittorrent"]
  category = "prowlarr"
  username = "${data.sops_file.servarr-secrets.data["servarr_username"]}"
  password = "${data.sops_file.servarr-secrets.data["servarr_password"]}"
}
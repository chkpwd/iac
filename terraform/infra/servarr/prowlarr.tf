resource "prowlarr_application_sonarr" "sonarr" {
  name                  = "sonarr"
  sync_level            = "fullSync"
  base_url              = "http://${media_host_ip}:${sonarr_port}"
  prowlarr_url          = "http://${media_host_ip}:${prowlarr_port}"
  api_key               = "${data.sops_file.servarr-secrets.data["sonarr_api_key"]}"
  sync_categories       = [5000, 5010, 5030]
  anime_sync_categories = [5070]
}

resource "prowlarr_application_radarr" "radarr" {
  name            = "radarr"
  sync_level      = "fullSync"
  base_url        = "http://${media_host_ip}:${radarr_port}"
  prowlarr_url    = "http://${media_host_ip}:${prowlarr_port}"
  api_key         = "${data.sops_file.servarr-secrets.data["radarr_api_key"]}"
  sync_categories = [2000, 2010, 2030]
}

resource "prowlarr_download_client_sabnzbd" "sabnzbd" {
  enable   = true
  priority = 1
  name     = "sabnzbd"
  host     = "${media_host_ip}"
  url_base = "/"
  port     = "${sabnzbd_port}"
  category = "prowlarr"
  api_key  = "${data.sops_file.servarr-secrets.data["sabnzbd_api_key"]}"
  username = "${data.sops_file.servarr-secrets.data["servarr_username"]}"
  password = "${data.sops_file.servarr-secrets.data["servarr_password"]}"
}

resource "prowlarr_download_client_qbittorrent" "qbiittorrent" {
  enable   = true
  priority = 2
  name     = "qbittorrent"
  host     = "${media_host_ip}"
  url_base = "/"
  port     = "${qbittorrent_port}"
  category = "prowlarr"
  username = "${data.sops_file.servarr-secrets.data["servarr_username"]}"
  password = "${data.sops_file.servarr-secrets.data["servarr_password"]}"
}
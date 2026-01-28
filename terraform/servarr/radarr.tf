resource "radarr_delay_profile" "default" {
  enable_usenet             = true
  enable_torrent            = true
  bypass_if_highest_quality = true
  usenet_delay              = 0
  torrent_delay             = 5
  tags                      = [1]
  preferred_protocol        = "usenet"
}

resource "radarr_download_client_sabnzbd" "sabnzbd" {
  enable         = true
  priority       = 1
  name           = "sabnzbd"
  host           = "sabnzbd.${var.cluster_media_domain}"
  url_base       = "/"
  port           = var.ports["sabnzbd"]
  movie_category = "movies"
  api_key        = data.external.bws_lookup.result["infra-media-secrets_sabnzbd_api_key"]
}

resource "radarr_download_client_qbittorrent" "qbittorrent" {
  enable         = true
  priority       = 1
  name           = "qbittorrent"
  host           = "qbittorrent.${var.cluster_media_domain}"
  url_base       = "/"
  movie_category = "radarr"
  port           = var.ports["qbittorrent"]
  first_and_last = false
  username       = data.external.bws_lookup.result["infra-media-secrets_servarr_username"]
  password       = data.external.bws_lookup.result["infra-media-secrets_servarr_password"]
}

resource "radarr_naming" "media_naming_configs" {
  #include_quality            = false
  rename_movies              = true
  replace_illegal_characters = true
  #replace_spaces             = false
  colon_replacement_format = "dash"
  standard_movie_format    = "{Movie OriginalTitle} ({Release Year}) [{Quality Title} {MediaInfo VideoBitDepth}bit {MediaInfo VideoCodec} {MediaInfo VideoDynamicRangeType} {MediaInfo AudioLanguages} {MediaInfo AudioCodec} {MediaInfo AudioChannels} -{Release Group}]{imdb-{ImdbId}}{tmdb-{TmdbId}}{edition-{Edition Tags}}"
  movie_folder_format      = "{Movie Title} ({Release Year}) [imdbid-{ImdbId}]"
}

resource "radarr_media_management" "media_settings_configs" {
  auto_unmonitor_previously_downloaded_movies = false
  recycle_bin                                 = ""
  recycle_bin_cleanup_days                    = 7
  download_propers_and_repacks                = "doNotPrefer"
  create_empty_movie_folders                  = false
  delete_empty_folders                        = true
  file_date                                   = "none"
  rescan_after_refresh                        = "always"
  auto_rename_folders                         = false
  paths_default_static                        = false
  set_permissions_linux                       = false
  chmod_folder                                = 755
  chown_group                                 = ""
  skip_free_space_check_when_importing        = true
  minimum_free_space_when_importing           = 100
  copy_using_hardlinks                        = true
  import_extra_files                          = true
  extra_file_extensions                       = "srt,nfo,png"
  enable_media_info                           = true
}

resource "radarr_root_folder" "standard_1080p" {
  path = "/data/films/1080p"
}

resource "radarr_root_folder" "standard_4k" {
  path = "/data/films/4k"
}

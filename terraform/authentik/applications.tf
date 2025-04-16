module "authentik-app-sonarr" {
  source = "../_modules/authentik/proxy_app"
  name   = "Sonarr"
  group  = "main"

  proxy_values = {
    internal        = ""
    external        = "https://sonarr.chkpwd.com"
    mode            = "forward_single"
    skip_path_regex = <<EOF
^/api
^/metrics
EOF
  }

  app_values = {
    meta_description = "Series Management"
    icon_url         = "https://cdn.jsdelivr.net/gh/selfhst/icons/webp/sonarr.webp"
  }

  access_group = [authentik_group.main.id]
}

module "authentik-app-radarr" {
  source = "../_modules/authentik/proxy_app"
  name   = "Radarr"
  group  = "main"

  proxy_values = {
    internal        = ""
    external        = "https://radarr.chkpwd.com"
    mode            = "forward_single"
    skip_path_regex = <<EOF
^/api
^/metrics
EOF
  }

  app_values = {
    meta_description = "Movie Management"
    icon_url         = "https://cdn.jsdelivr.net/gh/selfhst/icons/webp/radarr.webp"
  }

  access_group = [authentik_group.main.id]
}

module "authentik-app-prowlarr" {
  source = "../_modules/authentik/proxy_app"
  name   = "Prowlarr"
  group  = "main"

  proxy_values = {
    internal        = ""
    external        = "https://prowlarr.chkpwd.com"
    mode            = "forward_single"
    skip_path_regex = <<EOF
^/api
^/metrics
EOF
  }

  app_values = {
    meta_description = "Indexer Management"
    icon_url         = "https://cdn.jsdelivr.net/gh/selfhst/icons/webp/prowlarr.webp"
  }

  access_group = [authentik_group.main.id]
}

module "authentik-app-sabnzbd" {
  source = "../_modules/authentik/proxy_app"
  name   = "Sabnzbd"
  group  = "main"

  proxy_values = {
    internal        = ""
    external        = "https://sabnzbd.chkpwd.com"
    mode            = "forward_single"
    skip_path_regex = <<EOF
^/api
^/metrics
EOF
  }

  app_values = {
    meta_description = "Usenet Downloader"
    icon_url         = "https://cdn.jsdelivr.net/gh/selfhst/icons/webp/sabnzbd.webp"
  }

  access_group = [authentik_group.main.id]
}

module "authentik-app-miniflux" {
  source = "../_modules/authentik/oauth2_app"
  name   = "Miniflux"
  group  = "main"
  oauth2_values = {
    client_id         = "miniflux"
    client_secret     = data.external.bws_lookup.result["ns-tools-miniflux_client_secret"]
    property_mappings = data.authentik_property_mapping_provider_scope.sources.ids
    allowed_redirect_uris = [
      {
        matching_mode = "strict",
        url           = "https://miniflux.chkpwd.com/oauth2/oidc/callback",
      }
    ]
  }
  app_values = {
    icon_url         = "https://cdn.jsdelivr.net/gh/selfhst/icons/webp/miniflux.webp"
    meta_description = "RSS Feed Reader"
  }
  access_group = [
    authentik_group.main.id
  ]
}

module "authentik-app-bazarr" {
  source = "../_modules/authentik/proxy_app"
  name   = "Bazarr"
  group  = "main"

  proxy_values = {
    internal        = ""
    external        = "https://bazarr.chkpwd.com"
    mode            = "forward_single"
    skip_path_regex = <<EOF
^/api
^/metrics
EOF
  }

  app_values = {
    meta_description = "Subtitle Management"
    icon_url         = "https://cdn.jsdelivr.net/gh/selfhst/icons/webp/bazarr.webp"
  }

  access_group = [authentik_group.main.id]
}

module "authentik-app-maintainerr" {
  source = "../_modules/authentik/proxy_app"
  name   = "Maintainerr"
  group  = "main"

  proxy_values = {
    internal = ""
    external = "https://maintainerr.chkpwd.com"
    mode     = "forward_single"
  }

  app_values = {
    meta_description = "Media Cleanup Tool"
    icon_url         = "https://cdn.jsdelivr.net/gh/selfhst/icons/webp/maintainerr.webp"
  }

  access_group = [authentik_group.main.id]
}

module "authentik-app-semaphore-ui" {
  source = "../_modules/authentik/oauth2_app"
  name   = "Semaphore UI"
  group  = "main"
  oauth2_values = {
    client_id         = "semaphore"
    client_secret     = data.external.bws_lookup.result["infra-semaphore-secrets_oauth_client_secret"]
    property_mappings = data.authentik_property_mapping_provider_scope.sources.ids
    allowed_redirect_uris = [
      {
        matching_mode = "strict",
        url           = "https://semaphore.chkpwd.com/api/auth/oidc/authentik/redirect",
      }
    ]
  }
  app_values = {
    icon_url         = "https://cdn.jsdelivr.net/gh/selfhst/icons/webp/semaphore.webp"
    meta_description = "Task Runner"
  }
  access_group = [
    authentik_group.main.id
  ]
}

module "authentik-app-immich" {
  source = "../_modules/authentik/oauth2_app"
  name   = "Immich"
  group  = "main"
  oauth2_values = {
    client_id         = "immich"
    client_secret     = data.external.bws_lookup.result["ns-tools-immich_client_secret"]
    property_mappings = data.authentik_property_mapping_provider_scope.sources.ids
    allowed_redirect_uris = [
      {
        matching_mode = "strict",
        url           = "app.immich:///oauth-callback",
      },
      {
        matching_mode = "strict",
        url           = "https://immich.chkpwd.com/auth/login",
      },
      {
        matching_mode = "strict",
        url           = "https://immich.chkpwd.com/user-settings",
      }
    ]
  }
  app_values = {
    icon_url         = "https://cdn.jsdelivr.net/gh/selfhst/icons/webp/immich.webp"
    meta_description = "Photo Management"
  }
  access_group = [
    authentik_group.main.id,
    authentik_group.secondary.id
  ]
}

module "authentik-app-qbittorrent" {
  source = "../_modules/authentik/proxy_app"
  name   = "qBittorrent"
  group  = "main"

  proxy_values = {
    internal        = ""
    external        = "https://qbittorrent.chkpwd.com"
    mode            = "forward_single"
    skip_path_regex = <<EOF
^/api
^/metrics
EOF
  }

  app_values = {
    meta_description = "Torrent Downloader"
    icon_url         = "https://cdn.jsdelivr.net/gh/selfhst/icons/webp/qbittorrent.webp"
  }

  access_group = [authentik_group.main.id]
}

module "authentik-app-karakeep" {
  source = "../_modules/authentik/oauth2_app"
  name   = "karakeep"
  group  = "main"
  oauth2_values = {
    client_id         = "karakeep"
    client_secret     = data.external.bws_lookup.result["ns-tools-karakeep_oauth_client_secret"]
    property_mappings = data.authentik_property_mapping_provider_scope.sources.ids
    allowed_redirect_uris = [
      {
        matching_mode = "strict",
        url           = "https://karakeep.chkpwd.com/api/auth/callback/custom",
      },
    ]
  }
  app_values = {
    icon_url         = "https://cdn.jsdelivr.net/gh/selfhst/icons/webp/karakeep-light.webp"
    meta_description = "Bookmark Everything"
  }
  access_group = [
    authentik_group.main.id,
    authentik_group.secondary.id
  ]
}

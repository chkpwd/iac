module "authentik-app-sonarr" {
  source = "../_modules/authentik/proxy_app"
  name   = "Sonarr"
  group  = "main"

  proxy_values = {
    internal        = ""
    external        = "https://sonarr.local.chkpwd.com"
    mode            = "forward_single"
    skip_path_regex = <<EOF
^/api
^/metrics
EOF
  }

  app_values = {
    meta_description = "Series Management"
    icon_url         = "https://cdn.jsdelivr.net/gh/chkpwd/icons@main/png/sonarr.png"
  }

  access_group = [authentik_group.main.id]
}

module "authentik-app-radarr" {
  source = "../_modules/authentik/proxy_app"
  name   = "Radarr"
  group  = "main"

  proxy_values = {
    internal        = ""
    external        = "https://radarr.local.chkpwd.com"
    mode            = "forward_single"
    skip_path_regex = <<EOF
^/api
^/metrics
EOF
  }

  app_values = {
    meta_description = "Movie Management"
    icon_url         = "https://cdn.jsdelivr.net/gh/chkpwd/icons@main/png/radarr.png"
  }

  access_group = [authentik_group.main.id]
}

module "authentik-app-prowlarr" {
  source = "../_modules/authentik/proxy_app"
  name   = "Prowlarr"
  group  = "main"

  proxy_values = {
    internal        = ""
    external        = "https://prowlarr.local.chkpwd.com"
    mode            = "forward_single"
    skip_path_regex = <<EOF
^/api
^/metrics
EOF
  }

  app_values = {
    meta_description = "Indexer Management"
    icon_url         = "https://cdn.jsdelivr.net/gh/chkpwd/icons@main/png/prowlarr.png"
  }

  access_group = [authentik_group.main.id]
}

module "authentik-app-sabnzbd" {
  source = "../_modules/authentik/proxy_app"
  name   = "Sabnzbd"
  group  = "main"

  proxy_values = {
    internal        = ""
    external        = "https://sabnzbd.local.chkpwd.com"
    mode            = "forward_single"
    skip_path_regex = <<EOF
^/api
^/metrics
EOF
  }

  app_values = {
    meta_description = "Usenet Downloader"
    icon_url         = "https://cdn.jsdelivr.net/gh/chkpwd/icons@main/png/sabnzbd.png"
  }

  access_group = [authentik_group.main.id]
}

module "authentik-app-mainsail" {
  source = "../_modules/authentik/proxy_app"
  name   = "Mainsail"
  group  = "main"

  proxy_values = {
    internal = ""
    external = "https://mainsail.chkpwd.com"
    mode     = "forward_single"
  }

  app_values = {
    meta_description = "Klipper Management System"
    icon_url         = "https://cdn.jsdelivr.net/gh/chkpwd/icons@main/png/mainsail.png"
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
    property_mappings = data.authentik_scope_mapping.scopes.ids
    redirect_uris     = ["https://miniflux.chkpwd.com/oauth2/oidc/callback"]
  }
  app_values = {
    icon_url         = "https://cdn.jsdelivr.net/gh/chkpwd/icons@main/png/miniflux.png"
    meta_description = "RSS Feed Reader"
  }
  access_group = [
    authentik_group.main.id
  ]
}

module "authentik-app-jellyfin" {
  source = "../_modules/authentik/proxy_app"
  name   = "Jellyfin"
  group  = "main"

  proxy_values = {
    internal = ""
    external = "https://jellyfin.local.chkpwd.com"
    mode     = "forward_single"
  }

  app_values = {
    meta_description = "Usenet Downloader"
    icon_url         = "https://cdn.jsdelivr.net/gh/chkpwd/icons@main/png/jellyfin.png"
  }

  access_group = [authentik_group.main.id]
}

module "authentik-app-bazarr" {
  source = "../_modules/authentik/proxy_app"
  name   = "Bazarr"
  group  = "main"

  proxy_values = {
    internal        = ""
    external        = "https://bazarr.local.chkpwd.com"
    mode            = "forward_single"
    skip_path_regex = <<EOF
^/api
^/metrics
EOF
  }

  app_values = {
    meta_description = "Series Management"
    icon_url         = "https://cdn.jsdelivr.net/gh/chkpwd/icons@main/png/bazarr.png"
  }

  access_group = [authentik_group.main.id]
}

module "authentik-app-qbittorrent" {
  source = "../_modules/authentik/proxy_app"
  name   = "Qbittorrent"
  group  = "main"

  proxy_values = {
    internal        = ""
    external        = "https://qbittorrent.local.chkpwd.com"
    mode            = "forward_single"
    skip_path_regex = <<EOF
^/api
^/metrics
EOF
  }

  app_values = {
    meta_description = "Series Management"
    icon_url         = "https://cdn.jsdelivr.net/gh/chkpwd/icons@main/png/qbittorrent.png"
  }

  access_group = [authentik_group.main.id]
}

module "authentik-app-runwhen-local" {
  source = "../_modules/authentik/proxy_app"
  name   = "Runwhen Local"
  group  = "main"

  proxy_values = {
    internal = ""
    external = "https://runwhen-local.chkpwd.com"
    mode     = "forward_single"
  }

  app_values = {
    meta_description = "Usenet Downloader"
    icon_url         = "https://cdn.jsdelivr.net/gh/chkpwd/icons@main/png/runwhen-local.png"
  }

  access_group = [authentik_group.main.id]
}

module "authentik-app-stirling-pdf" {
  source = "../_modules/authentik/proxy_app"
  name   = "Stirling PDF"
  group  = "secondary"

  proxy_values = {
    internal = ""
    external = "https://stirling-pdf.chkpwd.com"
    mode     = "forward_single"
  }

  app_values = {
    meta_description = "PDF Tool"
    icon_url         = "https://cdn.jsdelivr.net/gh/chkpwd/icons@main/png/stirling-pdf.png"
  }

  access_group = [authentik_group.main.id, authentik_group.secondary.id]
}

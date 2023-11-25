module "authentik-app-sonarr" {
  source = "../_modules/authentik/proxy_app"
  name     = "Sonarr"
  icon_url = "https://cdn.jsdelivr.net/gh/walkxcode/dashboard-icons@master/png/sonarr.png"
  group    = "main"
  meta_description = "Series Management"
  internal = ""
  external = "https://sonarr.k8s.chkpwd.com"
  access_group = [
    authentik_group.main.id
  ]
}

module "authentik-app-radarr" {
  source = "../_modules/authentik/proxy_app"
  name     = "Radarr"
  icon_url =  "https://cdn.jsdelivr.net/gh/walkxcode/dashboard-icons@master/png/radarr.png"
  group    = "main"
  meta_description = "Movie Management"
  internal = ""
  external = "https://radarr.k8s.chkpwd.com"
  access_group = [
    authentik_group.main.id
  ]
}

module "authentik-app-prowlarr" {
  source = "../_modules/authentik/proxy_app"
  name     = "Prowlarr"
  icon_url = "https://cdn.jsdelivr.net/gh/walkxcode/dashboard-icons@master/png/prowlarr.png"
  group    = "main"
  meta_description = "Indexer Management"
  internal = ""
  external = "https://prowlarr.k8s.chkpwd.com"
  access_group = [
    authentik_group.main.id
  ]
}

module "authentik-app-sabnzbd" {
  source = "../_modules/authentik/proxy_app"
  name     = "Sabnzbd"
  icon_url = "https://cdn.jsdelivr.net/gh/walkxcode/dashboard-icons@master/png/sabnzbd.png"
  group    = "main"
  meta_description = "Usenet Downloader"
  internal = ""
  external = "https://sabnzbd.k8s.chkpwd.com"
  access_group = [
    authentik_group.main.id
  ]
}

module "authentik-app-mainsail" {
  source = "../_modules/authentik/proxy_app"
  name     = "Mainsail"
  icon_url = "https://raw.githubusercontent.com/mainsail-crew/docs/master/assets/img/logo.png"
  group    = "main"
  meta_description = "3D Printing Software"
  internal = ""
  external = "https://mainsail.chkpwd.com"
  access_group = [
    authentik_group.main.id
  ]
}

# module "authentik-app-miniflux" {
#   source = "../_modules/authentik/oauth_app"
#   name                = "miniflux"
#   group               = "main"
#   provider_type       = "openidconnect"
#   authorization_url   = "https://miniflux.chkpwd.com"
#   consumer_key        = "foo"
#   consumer_secret     = "bar"
#   access_group = [
#     authentik_group.main.id
#   ]
# }

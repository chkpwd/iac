module "authentik-app-podinfo" {
  source = "../_modules/authentik_app"

  name     = "PodInfo"
  group    = "main"
  internal = ""
  external = "https://podinfo.k8s.chkpwd.com"
  access_group = [
    authentik_group.main.id
  ]
}

module "authentik-app-sonarr" {
  source = "../_modules/authentik_app"

  name     = "Sonarr"
  group    = "main"
  internal = ""
  external = "https://sonarr.k8s.chkpwd.com"
  access_group = [
    authentik_group.main.id
  ]
}

module "authentik-app-radarr" {
  source = "../_modules/authentik_app"

  name     = "Radarr"
  group    = "main"
  internal = ""
  external = "https://radarr.k8s.chkpwd.com"
  access_group = [
    authentik_group.main.id
  ]
}

module "authentik-app-prowlarr" {
  source = "../_modules/authentik_app"

  name     = "Prowlarr"
  group    = "main"
  internal = ""
  external = "https://prowlarr.k8s.chkpwd.com"
  access_group = [
    authentik_group.main.id
  ]
}

module "authentik-app-sabnzbd" {
  source = "../_modules/authentik_app"

  name     = "Sabnzbd"
  group    = "main"
  internal = ""
  external = "https://sabnzbd.k8s.chkpwd.com"
  access_group = [
    authentik_group.main.id
  ]
}

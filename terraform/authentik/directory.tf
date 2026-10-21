resource "authentik_user" "main" {
  email    = "authentik@chkpwd.com"
  username = "chkpwd"
  name     = "chkpwd"
  password = data.external.bws_lookup.result["authentik_main_user_password"]

}

resource "authentik_user" "secondary" {
  username = "erykuh"
  name     = "erykuh"
  email    = "erykuh@chkpwd.com"
  password = data.external.bws_lookup.result["authentik_secondary_user_password"]
}

resource "random_password" "password" {
  length           = 16
  special          = true
  override_special = "!#$%&*()-_=+[]{}<>:?"
}

resource "authentik_user" "temp" {
  username = "ashley"
  name     = "ashley"
  email    = "ashyenc@gmail.com"
  password = random_password.password.result
}

resource "authentik_group" "main" {
  name         = "main"
  users        = [authentik_user.main.id]
  is_superuser = false
}

resource "authentik_group" "secondary" {
  name         = "secondary"
  users        = [authentik_user.secondary.id, authentik_user.temp.id]
  is_superuser = false
}

resource "authentik_token" "media" {
  user        = authentik_user.main.id
  identifier  = "media"
  expiring    = false
  description = "Media token"
  intent      = "app_password"
}

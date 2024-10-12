resource "random_password" "temp_password" {
  length           = 32
  special          = true
  override_special = "!#$%&*()-_=+[]{}<>:?"
}

resource "authentik_user" "main" {
  email = "authentik@chkpwd.com"
  username = "chkpwd"
  name     = "Default User"
  password = data.external.bws_lookup.result["ns-security-authentik_main_user_password"]

}

resource "authentik_user" "secondary" {
  username = "erykuh"
  name     = "Approving Wife"
  password = data.external.bws_lookup.result["ns-security-authentik_secondary_user_password"]
}

resource "authentik_user" "temp_user" {
  username = "temp"
  name     = "Temporary User"
  password = random_password.temp_password.result
}

resource "authentik_group" "main" {
  name         = "main"
  users        = [authentik_user.main.id]
  is_superuser = false
}

resource "authentik_group" "secondary" {
  name         = "secondary"
  users        = [authentik_user.temp_user.id, authentik_user.secondary.id]
  is_superuser = false
}

resource "authentik_token" "media" {
  user        = authentik_user.main.id
  identifier  = "media"
  expiring    = false
  description = "Media token"
  intent      = "app_password"
}

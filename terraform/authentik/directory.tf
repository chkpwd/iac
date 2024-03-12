resource "authentik_user" "main" {
  username = "chkpwd"
  name     = "Default User"
  password = data.external.bws_lookup.result["ns-security-authentik_main_user_password"]
}

resource "authentik_group" "main" {
  name         = "main"
  users        = [ authentik_user.main.id ]
  is_superuser = false
}

resource "authentik_token" "media" {
  user = authentik_user.main.id
  identifier = "media"
  expiring = false
  description = "Media token"
  intent = "app_password"
}

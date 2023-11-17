resource "authentik_user" "media" {
  username = "media"
  name     = "Media User"
  password = data.sops_file.authentik-secrets.data["authentik_media_group_pwd"]
}

resource "authentik_group" "media" {
  name         = "media"
  users        = [ authentik_user.media.id ]
  is_superuser = false
}

resource "authentik_user" "misc" {
  username = "misc"
  name     = "Misc User"
  password = data.sops_file.authentik-secrets.data["authentik_misc_group_pwd"]
}

resource "authentik_group" "misc" {
  name         = "misc"
  users        = [ authentik_user.misc.id ]
  is_superuser = false
}

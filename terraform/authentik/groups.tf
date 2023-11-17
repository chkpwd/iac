resource "authentik_user" "media" {
  username = "media"
  name     = "Media User"
}

resource "authentik_group" "media" {
  name         = "media"
  users        = [ authentik_user.media.id ]
  is_superuser = false
}

resource "authentik_user" "misc" {
  username = "misc"
  name     = "Misc User"
}

resource "authentik_group" "misc" {
  name         = "misc"
  users        = [ authentik_user.misc.id ]
  is_superuser = false
}
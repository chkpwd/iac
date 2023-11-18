resource "authentik_user" "main" {
  username = "chkpwd"
  name     = "Default User"
  password = data.sops_file.authentik-secrets.data["authentik_main_group_pwd"]
}

resource "authentik_group" "main" {
  name         = "main"
  users        = [ authentik_user.main.id ]
  is_superuser = false
}

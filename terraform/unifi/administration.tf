resource "unifi_setting_mgmt" "main" {
  site         = var.site
  auto_upgrade = false
  ssh_enabled  = true

  ssh_key {
    name = "main"
    type = "ssh-ed25519"
    key  = file(var.private_key_path)
    comment = "SSH Key for access"
  }
  
}
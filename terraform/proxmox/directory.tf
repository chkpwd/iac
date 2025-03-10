resource "proxmox_virtual_environment_role" "packer" {
  role_id = "packer"

  privileges = [
    "VM.Migrate",
    "Pool.Allocate",
    "Datastore.Audit",
    "Realm.AllocateUser",
    "VM.PowerMgmt",
    "Datastore.AllocateTemplate",
    "Datastore.Allocate",
    "User.Modify",
    "Sys.Audit",
    "VM.Audit",
    "SDN.Use",
    "Sys.Modify",
    "VM.Allocate",
    "VM.Monitor",
    "VM.Clone",
    "VM.Config.CPU",
    "VM.Config.Memory",
    "VM.Config.HWType",
    "VM.Config.Cloudinit",
    "VM.Config.Network",
    "VM.Config.CDROM",
    "VM.Config.Options",
    "VM.Config.Disk",
    "Datastore.AllocateSpace",
  ]
}

resource "proxmox_virtual_environment_user" "packer" {
  comment         = "Managed by Terraform"
  email           = "packer@pve"
  enabled         = true
  expiration_date = "2034-01-01T22:00:00Z"
  user_id         = "packer@pve"
  acl {
    role_id = proxmox_virtual_environment_role.packer.id
    path    = "/"

  }
}

resource "proxmox_virtual_environment_user_token" "packer" {
  comment         = "Managed by Terraform"
  expiration_date = "2033-01-01T22:00:00Z"
  token_name      = "tk1"
  user_id         = proxmox_virtual_environment_user.packer.user_id
}

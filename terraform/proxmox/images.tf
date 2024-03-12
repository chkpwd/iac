resource "proxmox_virtual_environment_download_file" "latest_bookworm_qcow2_nocloud" {
  content_type       = "iso"
  datastore_id       = "local"
  file_name          = "debian-12-nocloud-amd64.qcow2.img"
  node_name          = "pve1"
  url                = "https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-nocloud-amd64.qcow2"
  checksum           = "fc6e531badc3dd8e04180ef02580a4fe97d4e5ca0f66b5413256cd44d81bcef8032a79120ad3ec8671b7ec7013a1213758a2f2a192d1db2bb9aafd02675fef90"
  checksum_algorithm = "sha512"
}

resource "proxmox_virtual_environment_download_file" "latest_bookworm_netinstall" {
  content_type       = "iso"
  datastore_id       = "local"
  file_name          = "debian-12.5.0-amd64-netinst.iso"
  node_name          = "pve1"
  url                = "https://cdimage.debian.org/debian-cd/current/amd64/iso-cd/debian-12.5.0-amd64-netinst.iso"
  checksum           = "013f5b44670d81280b5b1bc02455842b250df2f0c6763398feb69af1a805a14f"
  checksum_algorithm = "sha256"
}

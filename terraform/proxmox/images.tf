resource "proxmox_virtual_environment_download_file" "debian_bookworm_qcow2_generic" {
  content_type       = "iso"
  datastore_id       = "local"
  file_name          = "debian-12-nocloud-amd64.qcow2.img"
  node_name          = var.node
  url                = "https://cloud.debian.org/images/cloud/bookworm/20250428-2096/debian-12-generic-amd64-20250428-2096.qcow2"
  checksum           = "dab5547daa93c45213970cd137826f671ae4b2f8b8f016398538e78a97080d5dffb79c9e9e314031361257f145ba9a3ef057a63e5212135c699495085951eb25"
  checksum_algorithm = "sha512"
}

resource "proxmox_virtual_environment_download_file" "debian_trixie_qcow2_generic" {
  content_type       = "iso"
  datastore_id       = "local"
  file_name          = "debian-13-genericcloud-amd64.qcow2.img"
  node_name          = var.node
  url                = "https://cloud.debian.org/images/cloud/trixie/daily/20250502-2100/debian-13-generic-amd64-daily-20250502-2100.qcow2"
  checksum           = "74576576973997dbbb2f7e0aaf06c2769e59958871ef8b7aa3ebc621c0722838886775a3e8c9c50fb82cc002d0ebef1a970a078c132e07e6dacc0523061cd5aa"
  checksum_algorithm = "sha512"
}

resource "proxmox_virtual_environment_download_file" "ubuntu_noble_cloud_image" { # TODO: use renovate to update the checksum
  content_type       = "iso"
  datastore_id       = "local"
  file_name          = "ubuntu-24.04-cloudimg-amd64.qcow.iso"
  node_name          = var.node
  url                = "https://cloud-images.ubuntu.com/noble/20250610/noble-server-cloudimg-amd64.img"
  checksum           = "92d2c4591af9a82785464bede56022c49d4be27bde1bdcf4a9fccc62425cda43"
  checksum_algorithm = "sha256"
}

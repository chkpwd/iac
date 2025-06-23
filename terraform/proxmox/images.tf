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
  url                = "https://cloud.debian.org/images/cloud/trixie/daily/20250619-2148/debian-13-generic-amd64-daily-20250619-2148.qcow2"
  checksum           = "046d9691b1a6026fd457b85c85476fa721249dd9379e23ab877bb34b2d6fa662994b03a23ffe7b527c5421cb1a69e81b6873c82f0e1ac9403bbaad263fffd3d8"
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

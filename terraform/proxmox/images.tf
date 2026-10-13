resource "proxmox_download_file" "debian_bookworm_qcow2_generic" {
  content_type       = "iso"
  datastore_id       = "local"
  file_name          = "debian-12-nocloud-amd64.qcow2.img"
  node_name          = var.node
  url                = "https://cloud.debian.org/images/cloud/bookworm/20250428-2096/debian-12-generic-amd64-20250428-2096.qcow2"
  checksum           = "dab5547daa93c45213970cd137826f671ae4b2f8b8f016398538e78a97080d5dffb79c9e9e314031361257f145ba9a3ef057a63e5212135c699495085951eb25"
  checksum_algorithm = "sha512"
}

resource "proxmox_download_file" "debian_trixie_qcow2_generic" {
  content_type       = "iso"
  datastore_id       = "local"
  file_name          = "debian-13-genericcloud-amd64.qcow2.img"
  node_name          = var.node
  url                = "https://cloud.debian.org/images/cloud/trixie/20260706-2531/debian-13-generic-amd64-20260706-2531.qcow2"
  checksum           = "aca6eefc7b87faddad617b197fb621c44cc2c440f7097d78ac06e113f78177f6b7a1a39a581fbb24c2513354ab6938e63e78730259ce204b53452e8186f53a37"
  checksum_algorithm = "sha512"
}

resource "proxmox_download_file" "ubuntu_noble_cloud_image" { # TODO: use renovate to update the checksum
  content_type       = "iso"
  datastore_id       = "local"
  file_name          = "ubuntu-24.04-cloudimg-amd64.qcow.iso"
  node_name          = var.node
  url                = "https://cloud-images.ubuntu.com/noble/20260615/noble-server-cloudimg-amd64.img"
  checksum           = "5fa5b05e5ec239858c4531485d6023b0896448c2df7c63b34f8dae6ea6051a44"
  checksum_algorithm = "sha256"
}

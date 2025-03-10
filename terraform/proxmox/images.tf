resource "proxmox_virtual_environment_download_file" "debian_bookworm_qcow2_nocloud" {
  content_type       = "iso"
  datastore_id       = "local"
  file_name          = "debian-12-nocloud-amd64.qcow2.img"
  node_name          = var.node
  url                = "https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-nocloud-amd64.qcow2"
  checksum           = "ebe11d9535585925fc491dbdb73fbd5d71d3b3735f26278e6013b0dd74055edd7d3f35e83ecd7767542af98595f7963ef7e6b9703a641bf8b8f4489918e309d0"
  checksum_algorithm = "sha512"
}

resource "proxmox_virtual_environment_download_file" "ubuntu_noble_cloud_image" {
  content_type       = "iso"
  datastore_id       = "local"
  file_name          = "ubuntu-24.04-cloudimg-amd64.qcow.iso"
  node_name          = var.node
  url                = "https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img"
  checksum           = "85af38f453feaa3d6fbc6aba3b2a843b5b10e8ce273a24047259bb7fa47ff4c5"
  checksum_algorithm = "sha256"
}

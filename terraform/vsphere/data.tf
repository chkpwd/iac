data "vsphere_datacenter" "dc" {
  name = var.vsphere_datacenter
}

data "vsphere_datastore" "media_datastore" {
  name          = "media-ds"
  datacenter_id = data.vsphere_datacenter.dc.id
}

# data "vsphere_folder" "cattles" {
#   path = "cattle"
# }

# data "vsphere_folder" "windows" {
#   path = "${data.vsphere_folder.cattles.path}/windows"
# }

# data "vsphere_folder" "linux" {
#   path = "${data.vsphere_folder.cattles.path}/linux"
# }

# data "vsphere_folder" "docker_windows" {
#   path = "${data.vsphere_folder.cattles.path}/${data.vsphere_folder.windows.path}/docker"
# }

# data "vsphere_folder" "docker_linux" {
#   path = "${data.vsphere_folder.cattles.path}/${data.vsphere_folder.linux.path}/docker"
# }

# data "vsphere_folder" "gaming" {
#   path = "${data.vsphere_folder.cattles.path}/${data.vsphere_folder.windows.path}/gaming"
# }

# data "vsphere_folder" "kubernetes" {
#   path = "${data.vsphere_folder.cattles.path}/${data.vsphere_folder.linux.path}/kubernetes"
# }

# data "vsphere_folder" "dev" {
#   path = "${data.vsphere_folder.cattles.path}/${data.vsphere_folder.linux.path}/dev"
# }

# data "vsphere_folder" "media" {
#   path = "${data.vsphere_folder.cattles.path}/${data.vsphere_folder.linux.path}/media"
# }
resource "vsphere_tag_category" "guest_machines_category" {
  name        = "guest_machines"
  description = "Managed by Terraform"
  cardinality = "MULTIPLE"

  associable_types = [
    "VirtualMachine",
    "Folder"
  ]
}

resource "vsphere_tag" "cattle" {
  name        = "cattle_node"
  category_id = vsphere_tag_category.guest_machines_category.id
  description = "Pulumi is better"
}

resource "vsphere_tag" "docker" {
  name        = "docker_node"
  category_id = vsphere_tag_category.guest_machines_category.id
  description = "/s virtual machines"
}

resource "vsphere_tag" "gaming" {
  name        = "gaming_node"
  category_id = vsphere_tag_category.guest_machines_category.id
  description = "I don't even game anymore"
}

resource "vsphere_tag" "kubernetes" {
  name        = "kubernetes_node"
  category_id = vsphere_tag_category.guest_machines_category.id
  description = "Pretends to be a developer"
}

resource "vsphere_tag" "dev" {
  name        = "dev_node"
  category_id = vsphere_tag_category.guest_machines_category.id
  description = "Pretends to be a developer"
}

resource "vsphere_tag" "windows" {
  name        = "windows_node"
  category_id = vsphere_tag_category.guest_machines_category.id
  description = "Crappy OS"
}

resource "vsphere_tag" "linux" {
  name        = "linux_node"
  category_id = vsphere_tag_category.guest_machines_category.id
  description = "Based OS"
}

resource "vsphere_tag" "media" {
  name        = "media_node"
  category_id = vsphere_tag_category.guest_machines_category.id
  description = "Consumerism at it's finest"
}

resource "vsphere_folder" "cattles" {
  path = "cattle"
  type = "vm"
  datacenter_id = data.vsphere_datacenter.dc.id
  tags = [vsphere_tag.cattle.id]
}

resource "vsphere_folder" "windows" {
  path = "${vsphere_folder.cattles.path}/windows"
  type = "vm"
  datacenter_id = data.vsphere_datacenter.dc.id
  tags = [vsphere_tag.kubernetes.id]
}

resource "vsphere_folder" "linux" {
  path = "${vsphere_folder.cattles.path}/linux"
  type = "vm"
  datacenter_id = data.vsphere_datacenter.dc.id
  tags = [vsphere_tag.linux.id]
}

resource "vsphere_folder" "docker_windows" {
  path = "${vsphere_folder.windows.path}/docker"
  type = "vm"
  tags = [vsphere_tag.docker.id]
  datacenter_id = data.vsphere_datacenter.dc.id
}

resource "vsphere_folder" "docker_linux" {
  path = "${vsphere_folder.linux.path}/docker"
  type = "vm"
  tags = [vsphere_tag.docker.id]
  datacenter_id = data.vsphere_datacenter.dc.id
}

resource "vsphere_folder" "gaming_linux" {
  path = "${vsphere_folder.linux.path}/gaming"
  type = "vm"
  tags = [vsphere_tag.docker.id]
  datacenter_id = data.vsphere_datacenter.dc.id
}

resource "vsphere_folder" "gaming_windows" {
  path = "${vsphere_folder.windows.path}/gaming"
  type = "vm"
  tags = [vsphere_tag.docker.id]
  datacenter_id = data.vsphere_datacenter.dc.id
}

resource "vsphere_folder" "kubernetes" {
  path = "${vsphere_folder.linux.path}/kubernetes"
  type = "vm"
  datacenter_id = data.vsphere_datacenter.dc.id
  tags = [vsphere_tag.kubernetes.id]
}

resource "vsphere_folder" "dev" {
  path = "${vsphere_folder.linux.path}/dev"
  type = "vm"
  datacenter_id = data.vsphere_datacenter.dc.id
  tags = [vsphere_tag.dev.id]
}

resource "vsphere_folder" "media" {
  path = "${vsphere_folder.linux.path}/media"
  type = "vm"
  datacenter_id = data.vsphere_datacenter.dc.id
  tags = [vsphere_tag.media.id]
}

resource "vsphere_folder" "personal_linux" {
  path = "${vsphere_folder.linux.path}/personal"
  type = "vm"
  datacenter_id = data.vsphere_datacenter.dc.id
  tags = [vsphere_tag.dev.id]
}

resource "vsphere_folder" "personal_windows" {
  path = "${vsphere_folder.windows.path}/personal"
  type = "vm"
  datacenter_id = data.vsphere_datacenter.dc.id
  tags = [vsphere_tag.dev.id]
}
resource "vsphere_tag_category" "guest_machines_category" {
  name        = "guest_machines"
  description = "Managed by Terraform"
  cardinality = "SINGLE"

  associable_types = [
    "VirtualMachine"
  ]
}

resource "vsphere_tag" "cattle" {
  name        = "cattle_node"
  category_id = vsphere_tag_category.guest_machines_category.id
  description = "Managed by Terraform"
}

resource "vsphere_tag" "docker" {
  name        = "docker_node"
  category_id = vsphere_tag_category.guest_machines_category.id
  description = "Managed by Terraform"
}

resource "vsphere_tag" "gaming" {
  name        = "gaming_node"
  category_id = vsphere_tag_category.guest_machines_category.id
  description = "Managed by Terraform"
}

resource "vsphere_tag" "kubernetes" {
  name        = "kubernetes_node"
  category_id = vsphere_tag_category.guest_machines_category.id
  description = "Managed by Terraform"
}

resource "vsphere_tag" "dev" {
  name        = "dev_node"
  category_id = vsphere_tag_category.guest_machines_category.id
  description = "Managed by Terraform"
}

resource "vsphere_folder" "cattles" {
  path = "cattle"
  type = "vm"
  datacenter_id = data.vsphere_datacenter.dc.id
  tags = [vsphere_tag.cattle.id]
}

resource "vsphere_folder" "docker" {
  path = "${vsphere_folder.cattles.path}/docker"
  type = "vm"
  tags = [vsphere_tag.docker.id]
  datacenter_id = data.vsphere_datacenter.dc.id
}

resource "vsphere_folder" "gaming" {
  path = "${vsphere_folder.cattles.path}/gaming"
  type = "vm"
  tags = [vsphere_tag.docker.id]
  datacenter_id = data.vsphere_datacenter.dc.id
}

resource "vsphere_folder" "kubernetes" {
  path = "${vsphere_folder.cattles.path}/kubernetes"
  type = "vm"
  datacenter_id = data.vsphere_datacenter.dc.id
  tags = [vsphere_tag.kubernetes.id]
}

resource "vsphere_folder" "dev" {
  path = "${vsphere_folder.cattles.path}/dev"
  type = "vm"
  datacenter_id = data.vsphere_datacenter.dc.id
  tags = [vsphere_tag.dev.id]
}
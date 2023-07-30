data "vsphere_datacenter" "dc" {
  name = var.vsphere_datacenter
}

data "vsphere_datastore" "media_datastore" {
  name          = "media-ds"
  datacenter_id = data.vsphere_datacenter.dc.id
}
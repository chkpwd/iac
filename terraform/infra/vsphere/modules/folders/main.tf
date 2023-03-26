#===============================================================================
# vSphere Data
#===============================================================================

data "vsphere_datacenter" "dc" {
  name = "${var.vsphere_datacenter}"
}

#===============================================================================
# vSphere Resources
#===============================================================================

resource "vsphere_folder" "cattles" {
  path = "cattles"
  type = "vm"
  datacenter_id = "${data.vsphere_datacenter.dc.id}"
}
data "vsphere_datacenter" "dc" {
  name = var.vsphere_datacenter
}

data "vsphere_host" "main" {
  name          = "octane.${var.domain}"
  datacenter_id = data.vsphere_datacenter.dc.id
}

data "vsphere_host_pci_device" "nvidia_1080" {
  host_id    = data.vsphere_host.main.id
  name_regex = "1080"
}

data "vsphere_host_pci_device" "nvidia_1050ti" {
  host_id    = data.vsphere_host.main.id
  name_regex = "1050"
}

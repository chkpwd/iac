data "vsphere_datacenter" "datacenter" {
  name = var.vsphere_datacenter
}

data "vsphere_compute_cluster" "cluster" {
  name          = var.vsphere_cluster
  datacenter_id = data.vsphere_datacenter.datacenter.id
}

data "vsphere_datastore" "datastore" {
  name          = var.vm_datastore
  datacenter_id = data.vsphere_datacenter.datacenter.id
}

data "vsphere_host" "host" {
  name          = "octane.${var.domain}"
  datacenter_id = data.vsphere_datacenter.datacenter.id
}

data "vsphere_network" "network" {
  name          = var.network_spec.network_id
  datacenter_id = data.vsphere_datacenter.datacenter.id
}

data "vsphere_ovf_vm_template" "ovfRemote" {
  name              = var.vm_name
  host_system_id    = data.vsphere_host.host.id
  disk_provisioning = "thin"
  resource_pool_id  = data.vsphere_compute_cluster.cluster.resource_pool_id
  datastore_id      = data.vsphere_datastore.datastore.id
  remote_ovf_url    = "https://github.com/siderolabs/talos/releases/download/v1.4.8/vmware-amd64.ova"
  ovf_network_map   = {
    "VM Network" : data.vsphere_network.network.id
  }
}

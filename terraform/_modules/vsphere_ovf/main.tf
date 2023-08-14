resource "vsphere_virtual_machine" "remote-ovf" {
  name                 = var.vm_name
  datacenter_id        = data.vsphere_datacenter.datacenter.id
  datastore_id         = data.vsphere_datastore.datastore.id
  host_system_id       = data.vsphere_host.host.id
  resource_pool_id     = data.vsphere_ovf_vm_template.ovfRemote.resource_pool_id

  num_cpus             = var.spec.cpu
  memory               = var.spec.memory
  nested_hv_enabled    = true

  sync_time_with_host = true

  firmware = "efi"

  wait_for_guest_net_timeout = 0
  wait_for_guest_ip_timeout  = 0

  ovf_deploy {
    allow_unverified_ssl_cert = false
    remote_ovf_url            = var.remote_ovf_url
    disk_provisioning         = "thin"
    ovf_network_map = {
      "Network 1" = data.vsphere_network.network.id
    }
  }

}
module "ansible-vm" {
 source      = "./modules/ansible-test"
 vm_count = 3
 ssh_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICsJocZS/OZ/4ZrLAxFOppiVMTym5oDkfHiir3YFg8mQ"
 vm_user = "hyoga"
 ip_address = "172.16.16.20"
 gateway = "172.16.16.1"
 bridge = "vmbr0"
 disk_size = 15
 cpu_count = 2
 ram_size = 2048
 storage_location = "Arenas"
 vlan_tag = "0"
 vm_name = "ansible-vm"
}

resource "vsphere_virtual_machine" "vm" {
  name             = var.name
  resource_pool_id = data.vsphere_compute_cluster.cluster.resource_pool_id
  datastore_id     = data.vsphere_datastore.datastore.id

  num_cpus             = var.cpu
  num_cores_per_socket = var.cores-per-socket
  memory               = var.ram
  guest_id             = var.vm-guest-id

  network_interface {
    network_id   = data.vsphere_network.network.id
    adapter_type = data.vsphere_virtual_machine.template.network_interface_types[0]
  }

  disk {
    label            = "${var.name}-disk"
    thin_provisioned = data.vsphere_virtual_machine.template.disks.0.thin_provisioned
    eagerly_scrub    = data.vsphere_virtual_machine.template.disks.0.eagerly_scrub
    size             = var.disksize == "" ? data.vsphere_virtual_machine.template.disks.0.size : var.disksize 
  }

  clone {
    template_uuid = data.vsphere_virtual_machine.template.id
  }
  extra_config = {
    "guestinfo.metadata"          = base64encode(templatefile("${path.module}/templates/metadata.yaml", local.templatevars))
    "guestinfo.metadata.encoding" = "base64"
    "guestinfo.userdata"          = base64encode(templatefile("${path.module}/templates/userdata.yaml", local.templatevars))
    "guestinfo.userdata.encoding" = "base64"
  }
  lifecycle {
    ignore_changes = [
      annotation,
      clone[0].template_uuid,
      clone[0].customize[0].dns_server_list,
      clone[0].customize[0].network_interface[0]
    ]
  }
}
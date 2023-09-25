#===============================================================================
# vSphere Resources
#===============================================================================

resource "vsphere_virtual_machine" "main" {
  tags   = var.spec.tags
  folder = var.spec.folder

  name             = var.vm_name
  resource_pool_id = data.vsphere_compute_cluster.cluster.resource_pool_id
  datastore_id     = data.vsphere_datastore.datastore.id

  num_cpus = var.spec.cpu
  memory   = var.spec.memory
  guest_id = data.vsphere_virtual_machine.template.guest_id
  nested_hv_enabled = var.spec.enable_hv

  sync_time_with_host = true
  memory_reservation  = var.spec.memory_reservation == true ? var.spec.memory : null
  firmware = "efi"

  pci_device_id = var.spec.pci_device != null ? var.spec.pci_device : null

  network_interface {
    network_id   = data.vsphere_network.network.id
    adapter_type = "vmxnet3"
    use_static_mac = var.network_spec.static_mac_addr
    mac_address  = var.network_spec.mac_address != null ? var.network_spec.mac_address : null
  }

  disk {
    size  = var.spec.disk_size
    label = "${var.vm_name}.vmdk"
  }

  dynamic "disk" {
    for_each = var.spec.additional_disks != null ? var.spec.additional_disks : []
    content {
      label            = "extra-disk-${disk.key}"
      datastore_id     = disk.value.datastore_id != null ? disk.value.datastore_id : null
      attach           = disk.value.attach_disk
      size             = disk.value.size
      eagerly_scrub    = false
      thin_provisioned = true
      unit_number      = disk.key + 1
    }
  }

  clone {
    template_uuid = data.vsphere_virtual_machine.template.id
    linked_clone  = var.spec.linked_clone

    dynamic "customize" {
      for_each = length(regexall("^win.*", data.vsphere_virtual_machine.template.guest_id)) == 0 ? [1] : []
      content {
        timeout = "20"

        linux_options {
          host_name = var.vm_name
          domain    = var.vm_domain
        }
        network_interface {}
      }
    }
  }

  lifecycle {
    ignore_changes = [
      firmware,
      clone[0].template_uuid,
      clone[0].customize,
      pci_device_id,
      ept_rvi_mode,
      hv_mode
    ]
  }
}
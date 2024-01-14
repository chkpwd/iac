#===============================================================================
# vSphere Resources
#===============================================================================

resource "vsphere_virtual_machine" "main" {
  tags   = var.spec.tags
  folder = var.spec.folder

  name             = var.vm_name
  resource_pool_id = data.vsphere_compute_cluster.cluster.resource_pool_id
  host_system_id   = data.vsphere_host.main.id
  datastore_id     = data.vsphere_datastore.datastore.id

  num_cpus  = var.spec.cpu
  memory    = var.spec.memory
  guest_id  = data.vsphere_virtual_machine.template.guest_id
  scsi_type = null != var.spec.scsi_type ? var.spec.scsi_type : null
  nested_hv_enabled = var.spec.enable_hv

  sync_time_with_host = true
  memory_reservation  = var.spec.memory_reservation == true ? var.spec.memory : null
  firmware = "efi"

  pci_device_id = null != var.spec.pci_device ? var.spec.pci_device : null

  network_interface {
    network_id   = data.vsphere_network.network.id
    adapter_type = "vmxnet3"
    use_static_mac = var.network_spec.static_mac_addr
    mac_address  = null != var.network_spec.mac_address ? var.network_spec.mac_address : null
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
      # Check if it's a Windows VM
      for_each = length(regexall("^win.*", data.vsphere_virtual_machine.template.guest_id)) > 0 ? ["windows"] : ["linux"]

      content {
        timeout = "20"

        dynamic "linux_options" {
          for_each = customize.value == "linux" ? [1] : []
          content {
            host_name = var.vm_name
            domain    = var.vm_domain
          }
        }

        dynamic "windows_options" {
          for_each = customize.value == "windows" ? [1] : []
          content {
            computer_name  = var.vm_name
            workgroup      = "CHKPWD"
            admin_password = "terraform"
          }
        }

        network_interface {}
      }
    }
  }

  lifecycle {
    ignore_changes = [
      guest_id,
      firmware,
      clone[0].template_uuid,
      clone[0].customize,
      pci_device_id,
      ept_rvi_mode,
      hv_mode
    ]
  }

  extra_config = null != var.spec.extra_config ? var.spec.extra_config : null
}

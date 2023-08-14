locals {
  kubernetes_version = "1.27.4"
  netmask            = 24
  gateway            = "172.16.30.1"
  nameservers        = ["1.1.1.1", "1.0.0.1"]
  timeservers        = ["pool.ntp.org"]
  cluster_vip        = "172.16.30.200"
  cluster_endpoint   = "https://${local.cluster_vip}:6443" # k8s kube-apiserver endpoint.
  
  controller_nodes = [
    for i in range(var.controller_count) : {
      name    = "c${i}"
      address = "172.16.30.${10 + i}"
    }
  ]

  worker_nodes = [
    for i in range(var.worker_count) : {
      name    = "w${i}"
      address = "172.16.30.${20 + i}"
    }
  ]

  common_machine_config = {
    cluster = {
      # see https://www.talos.dev/v1.3/talos-guides/discovery/
      # see https://www.talos.dev/v1.3/reference/configuration/#clusterdiscoveryconfig
      discovery = {
        enabled = true
        registries = {
          kubernetes = {
            disabled = false
          }
          service = {
            disabled = true
          }
        }
      }

      extraManifests = [
        "https://github.com/mologie/talos-vmtoolsd/releases/download/0.3.1/talos-vmtoolsd-0.3.1.yaml"
      ]
    }
  }
}

# see https://www.terraform.io/docs/providers/vsphere/r/virtual_machine.html
resource "vsphere_virtual_machine" "controller" {
  count                       = var.controller_count
  # folder                      = "kubernetes"
  name                        = "${var.prefix}-${local.controller_nodes[count.index].name}"
  guest_id                    = data.vsphere_virtual_machine.talos_template.guest_id
  firmware                    = data.vsphere_virtual_machine.talos_template.firmware
  num_cpus                    = 4
  num_cores_per_socket        = 4
  memory                      = 2 * 1024
  wait_for_guest_net_routable = false
  wait_for_guest_net_timeout  = 0
  wait_for_guest_ip_timeout   = 0
  enable_disk_uuid            = true # NB the VM must have disk.EnableUUID=1 for, e.g., k8s persistent storage.
  resource_pool_id            = data.vsphere_compute_cluster.compute_cluster.resource_pool_id
  datastore_id                = data.vsphere_datastore.datastore.id
  scsi_type                   = data.vsphere_virtual_machine.talos_template.scsi_type

  disk {
    unit_number      = 0
    label            = "os"
    size             = max(data.vsphere_virtual_machine.talos_template.disks.0.size, 40) # [GiB]
    eagerly_scrub    = data.vsphere_virtual_machine.talos_template.disks.0.eagerly_scrub
    thin_provisioned = data.vsphere_virtual_machine.talos_template.disks.0.thin_provisioned
  }

  network_interface {
    network_id   = data.vsphere_network.network.id
    adapter_type = data.vsphere_virtual_machine.talos_template.network_interface_types.0
  }

  clone {
    template_uuid = data.vsphere_virtual_machine.talos_template.id
  }

  # NB this extra_config data ends-up inside the VM .vmx file.
  extra_config = {
    "guestinfo.talos.config" = base64encode(talos_machine_configuration_controlplane.controller[count.index].machine_config)
  }

}

# see https://www.terraform.io/docs/providers/vsphere/r/virtual_machine.html
resource "vsphere_virtual_machine" "worker" {
  count                       = var.worker_count
  # folder                      = vsphere_folder.folder.path
  name                        = "${var.prefix}-${local.worker_nodes[count.index].name}"
  guest_id                    = data.vsphere_virtual_machine.talos_template.guest_id
  firmware                    = data.vsphere_virtual_machine.talos_template.firmware
  num_cpus                    = 4
  num_cores_per_socket        = 4
  memory                      = 2 * 1024
  wait_for_guest_net_routable = false
  wait_for_guest_net_timeout  = 0
  wait_for_guest_ip_timeout   = 0
  enable_disk_uuid            = true # NB the VM must have disk.EnableUUID=1 for, e.g., k8s persistent storage.
  resource_pool_id            = data.vsphere_compute_cluster.compute_cluster.resource_pool_id
  datastore_id                = data.vsphere_datastore.datastore.id
  scsi_type                   = data.vsphere_virtual_machine.talos_template.scsi_type

  disk {
    unit_number      = 0
    label            = "os"
    size             = max(data.vsphere_virtual_machine.talos_template.disks.0.size, 40) # [GiB]
    eagerly_scrub    = data.vsphere_virtual_machine.talos_template.disks.0.eagerly_scrub
    thin_provisioned = data.vsphere_virtual_machine.talos_template.disks.0.thin_provisioned
  }

  network_interface {
    network_id   = data.vsphere_network.network.id
    adapter_type = data.vsphere_virtual_machine.talos_template.network_interface_types.0
  }

  clone {
    template_uuid = data.vsphere_virtual_machine.talos_template.id
  }

  # NB this extra_config data ends-up inside the VM .vmx file.
  extra_config = {
    "guestinfo.talos.config" = base64encode(talos_machine_configuration_worker.worker[count.index].machine_config)
  }

}
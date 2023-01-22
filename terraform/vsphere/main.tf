terraform {
  required_providers {
    vsphere = {
      source = "hashicorp/vsphere"
      version = "2.2.0"
    }
  }
}

provider "vsphere" {
  user                 = var.vsphere_user
  password             = var.vsphere_password
  vsphere_server       = var.vsphere_server
  allow_unverified_ssl = true
}

data "vsphere_datacenter" "dc" {
  name = "The Outlands"
}

data "vsphere_compute_cluster" "cluster" {
  name          = var.vsphere_cluster
  datacenter_id = data.vsphere_datacenter.dc.id
}

# Retrieve datastore information on vsphere
data "vsphere_datastore" "datastore" {
  name          = "datastore"
  datacenter_id = data.vsphere_datacenter.dc.id
}

# Retrieve network information on vsphere
data "vsphere_network" "network" {
  name          = "VM Network"
  datacenter_id = data.vsphere_datacenter.dc.id
}

# Retrieve template information on vsphere
data "vsphere_virtual_machine" "template" {
  name          = "Deb11-Template"
  datacenter_id = data.vsphere_datacenter.dc.id
}

#### VM CREATION ####

# Set vm parameters
resource "vsphere_virtual_machine" "vm" {
  name             = "vm-one"
  num_cpus         = 1
  memory           = 1024
  datastore_id     = data.vsphere_datastore.datastore.id
  resource_pool_id = data.vsphere_compute_cluster.cluster.resource_pool_id
  guest_id         = data.vsphere_virtual_machine.template.guest_id

  # Set network parameters
  network_interface {
    network_id = data.vsphere_network.network.id
  }

  disk {
    label            = "vm-one.vmdk"
    size             = "${data.vsphere_virtual_machine.template.disks.0.size}"
    eagerly_scrub    = "${data.vsphere_virtual_machine.template.disks.0.eagerly_scrub}"
    thin_provisioned = "${data.vsphere_virtual_machine.template.disks.0.thin_provisioned}"
  }
  
  clone {
    template_uuid = data.vsphere_virtual_machine.template.id
    linked_clone  = "false"

    customize {
      linux_options {
        host_name = "vm-one"
        domain    = "vm-one.typhon.tech"
      }

      network_interface {
        ipv4_address    = "172.16.16.65"
        ipv4_netmask    = 24
        dns_server_list = ["172.16.16.1", "8.8.8.8"]
      }

      ipv4_gateway = "172.16.16.1"
    }
  }

  # # Execute script on remote vm after this creation
  # provisioner "remote-exec" {
  #   script = "scripts/example-script.sh"
  #   connection {
  #     type     = "ssh"
  #     user     = "root"
  #     password = "VMware1!"
  #     host     = vsphere_virtual_machine.demo.default_ip_address 
  #  }
  # }
}
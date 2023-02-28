#===============================================================================
# vSphere Data
#===============================================================================

data "vsphere_datacenter" "dc" {
  name = "${var.vsphere_datacenter}"
}

data "vsphere_compute_cluster" "cluster" {
  name          = "${var.vsphere_cluster}"
  datacenter_id = "${data.vsphere_datacenter.dc.id}"
}

data "vsphere_datastore" "datastore" {
  name          = "${var.vm_datastore}"
  datacenter_id = "${data.vsphere_datacenter.dc.id}"
}

data "vsphere_network" "network" {
  name          = "${var.vm_network}"
  datacenter_id = "${data.vsphere_datacenter.dc.id}"
}

data "vsphere_virtual_machine" "template" {
  name          = "${var.vm_template}"
  datacenter_id = "${data.vsphere_datacenter.dc.id}"
}
 
 locals {
  templatevars = {
    name         = var.vm_name,
    ipv4_address = var.vm_ip,
    ipv4_gateway = var.vm_gateway,
    dns_server_1 = var.vm_dns[0],
    public_key   = var.vm_public_key,
    ssh_username = var.ssh_username
  }
}

#===============================================================================
# vSphere Resources
#===============================================================================

resource "vsphere_virtual_machine" "standalone" {
  name             = "${var.vm_name}"
  resource_pool_id = "${data.vsphere_compute_cluster.cluster.resource_pool_id}"
  datastore_id     = "${data.vsphere_datastore.datastore.id}"

  num_cpus = "${var.vm_cpu}"
  memory   = "${var.vm_ram}"
  guest_id = "${data.vsphere_virtual_machine.template.guest_id}"

  network_interface {
    network_id   = "${data.vsphere_network.network.id}"
    adapter_type = "${data.vsphere_virtual_machine.template.network_interface_types[0]}"
  }

  disk {
    label            = "${var.vm_name}.vmdk"
    size             = "${var.vm_disk_size}"
    eagerly_scrub    = "${data.vsphere_virtual_machine.template.disks.0.eagerly_scrub}"
    thin_provisioned = "${data.vsphere_virtual_machine.template.disks.0.thin_provisioned}"
  }

  clone {
    template_uuid = "${data.vsphere_virtual_machine.template.id}"
    linked_clone  = "${var.vm_linked_clone}"

    customize {
      timeout = "20"

      linux_options {
        host_name = "${var.vm_name}"
        domain    = "${var.vm_domain}"
      }

      network_interface {
        ipv4_address = "${var.vm_ip}"
        ipv4_netmask = "${var.vm_netmask}"
      }

      ipv4_gateway    = "${var.vm_gateway}"
      dns_server_list = "${var.vm_dns}"
      dns_suffix_list = "${var.dns_suffix}"
    }
  }
  extra_config = {
    "guestinfo.metadata"          = base64encode(templatefile("${path.module}/templates/metadata.yml", local.templatevars))
    "guestinfo.metadata.encoding" = "base64"
    "guestinfo.userdata"          = base64encode(templatefile("${path.module}/templates/userdata.yml", local.templatevars))
    "guestinfo.userdata.encoding" = "base64"
  }
  lifecycle {
    ignore_changes = [
      annotation,
      clone[0].template_uuid,
      clone[0].customize[0].dns_server_list,
      clone[0].customize[0].network_interface[0],
      clone[0].customize[0].dns_suffix_list,
      disk[2].size,
      extra_config
    ]
  }
  
  # provisioner "remote-exec" {
  #   inline = ["echo Done!"]
  
  #   connection {
  #     host        = local.templatevars.ipv4_address
  #     type        = "ssh"
  #     user        = "${var.ssh_username}"
  #     password    = "${var.ssh_password}"
  #     #agent = true
  #     #private_key = "${file("~/.ssh/id_ed25519")}"
  # }
  # }

  #provisioner "local-exec" {
  #  command = "ansible-playbook /home/hyoga/code/boilerplates/ansible/playbooks/setup_ha_server.yml --private-key ~/.ssh/id_ed25519 -i /home/hyoga/code/boilerplates/ansible/inventory/clients.yml"
  #}
}

# resource "vsphere_virtual_machine" "windows" {

# }
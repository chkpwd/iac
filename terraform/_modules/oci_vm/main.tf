data "oci_identity_availability_domain" "ad" {
  compartment_id = data.sops_file.oci-secrets.data["oci_tenancy_ocid"]
  ad_number      = var.oci_availability_domain_number
}

data "http" "cf_ips" {
  url = "https://www.cloudflare.com/ips-v4"
  request_headers = {
    Accept = "text/plain"
  }
}

locals {
  cf_ips = split("\n", data.http.cf_ips.response_body)
}

resource "oci_core_instance" "instance" {
  display_name          = var.instance_spec.name
  availability_domain   = data.oci_identity_availability_domain.ad.name
  compartment_id        = data.sops_file.oci-secrets.data["oci_tenancy_ocid"]
  shape                 = var.instance_spec.shape
  state                 = "RUNNING"
  preserve_boot_volume  = false

  shape_config {
    ocpus         = var.instance_spec.cpus
    memory_in_gbs = var.instance_spec.memory_gb
  }

  source_details {
    source_type             = "image"
    source_id               = var.instance_spec.image_id
    boot_volume_size_in_gbs = var.instance_spec.disk_size
  }

  availability_config {
    recovery_action = "RESTORE_INSTANCE"
  }

  create_vnic_details {
    subnet_id                 = var.instance_spec.network.subnet_id
    display_name              = var.instance_spec.network.vnic_label
    hostname_label            = var.instance_spec.network.hostname
    assign_public_ip          = var.instance_spec.network.assign_public_ip
    assign_private_dns_record = var.instance_spec.network.assign_private_dns_record
    private_ip                = var.instance_spec.network.private_ip
    nsg_ids                   = [oci_core_network_security_group.nsg.id]
  }

  metadata = {
    ssh_authorized_keys = var.instance_spec.ssh_authorized_keys
  }
}

resource "oci_core_network_security_group" "nsg" {
  compartment_id  = data.sops_file.oci-secrets.data["oci_tenancy_ocid"]
  vcn_id          = var.instance_spec.network.vcn_id
  display_name    = "${var.instance_spec.name} NSG"
}

resource "oci_core_network_security_group_security_rule" "ping-all" {
  network_security_group_id = oci_core_network_security_group.nsg.id

  description = "Allow ICMP ECHO from all"
  direction   = "INGRESS"
  protocol    = 1
  source      = "0.0.0.0/0"
  source_type = "CIDR_BLOCK"
  stateless   = false
  icmp_options {
    type = "8"
    }
}

resource "oci_core_network_security_group_security_rule" "http" {
  network_security_group_id = oci_core_network_security_group.nsg.id

  for_each    = toset(local.cf_ips)

  description = "Allow HTTP from CF"
  direction   = "INGRESS"
  protocol    = 6
  source      = each.key
  source_type = "CIDR_BLOCK"
  stateless   = false
  tcp_options {
    destination_port_range {
      min = 80
      max = 80
    }
  }
}

resource "oci_core_network_security_group_security_rule" "https" {
  network_security_group_id = oci_core_network_security_group.nsg.id

  for_each    = toset(local.cf_ips)

  description = "Allow HTTPS from CF"
  direction   = "INGRESS"
  protocol    = 6
  source      = each.key
  source_type = "CIDR_BLOCK"
  stateless   = false
  tcp_options {
    destination_port_range {
      min = 443
      max = 443
    }
  }
}

resource "oci_core_network_security_group_security_rule" "ssh" {
  for_each = {for index, ip in var.ssh_allowed_ips: ip.description => ip}

  network_security_group_id = oci_core_network_security_group.nsg.id

  description = "Allow SSH from ${each.value.description}"
  direction   = "INGRESS"
  protocol    = 6
  source      = each.value.ip
  source_type = "CIDR_BLOCK"
  stateless   = false
  tcp_options {
    destination_port_range {
      min = 22
      max = 22
    }
  }
}

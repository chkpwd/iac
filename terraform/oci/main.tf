module "ct-01-aarch64" {
  source                         = "../_modules/oci_vm"
  instance_spec                  = {
    name                         = "ct-01-aarch64"
    cpus                         = 1
    memory_gb                    = 6
    disk_size                    = 50
    shape                        = "VM.Standard.A1.Flex" 
    image_id                     = "ocid1.image.oc1.iad.aaaaaaaa7bvpvpgorsj2ciivlrxd4acxcjpbuhfv26pld3qnhjav5hpamm5q"
    network                      = {
      subnet_id                  = "${data.sops_file.oci-secrets.data["oci_subnet_ocid"]}"
      vnic_label                 = "Primaryvnic"
      hostname                   = "ct-01-aarch64"
      assign_public_ip           = true
      assign_private_dns_record  = true
    }
    ssh_authorized_keys          = "${data.sops_file.oci-secrets.data["ssh_pub_key"]}"
  }

  ssh_allowed_ips                = [
    {
      description                = "Public IP for homelab"
      ip                         = "${data.sops_file.oci-secrets.data["public_address"]}/32"
    }
  ]
  oci_availability_domain_number = var.availability_domain
}

module "ct-01-x86" {
  source                         = "../_modules/oci_vm"
  instance_spec                  = {
    name                         = "ct-01-x86"
    cpus                         = 1
    memory_gb                    = 1
    disk_size                    = 50
    shape                        = "VM.Standard.E2.1.Micro" 
    image_id                     = "ocid1.image.oc1.iad.aaaaaaaaau2eo3mjbgtmjvocmvx5xbhcmj2ay3mvowdzffxhdiql5gnhxjqa"
    network                      = {
      subnet_id                  = "${data.sops_file.oci-secrets.data["oci_subnet_ocid"]}"
      vnic_label                 = "Primaryvnic"
      hostname                   = "ct-01-x86"
      assign_public_ip           = true
      assign_private_dns_record  = true
    }
    ssh_authorized_keys          = "${data.sops_file.oci-secrets.data["ssh_pub_key"]}"
  }

  ssh_allowed_ips                = [
    {
      description                = "Public IP for homelab"
      ip                         = "${data.sops_file.oci-secrets.data["public_address"]}/32"
    }
  ]
  oci_availability_domain_number = 2
}

module "ct-02-x86" {
  source                         = "../_modules/oci_vm"
  instance_spec                  = {
    name                         = "ct-02-x86"
    cpus                         = 1
    memory_gb                    = 1
    disk_size                    = 50
    shape                        = "VM.Standard.E2.1.Micro" 
    image_id                     = "ocid1.image.oc1.iad.aaaaaaaaau2eo3mjbgtmjvocmvx5xbhcmj2ay3mvowdzffxhdiql5gnhxjqa"
    network                      = {
      subnet_id                  = "${data.sops_file.oci-secrets.data["oci_subnet_ocid"]}"
      vnic_label                 = "Primaryvnic"
      hostname                   = "ct-02-x86"
      assign_public_ip           = true
      assign_private_dns_record  = true
    }
    ssh_authorized_keys          = "${data.sops_file.oci-secrets.data["ssh_pub_key"]}"
  }

  ssh_allowed_ips                = [
    {
      description                = "Public IP for homelab"
      ip                         = "${data.sops_file.oci-secrets.data["public_address"]}/32"
    }
  ]
  oci_availability_domain_number = 2
}
packer {
  required_version = ">= 1.8.4"
  required_plugins {
    vsphere = {
      version = ">= v1.1.0"
      source  = "github.com/hashicorp/vsphere"
    }
  }
}

locals {
  preseed_config = {
    "/preseed.cfg" = templatefile("${abspath(path.root)}/files/preseed.pkrtpl.hcl", {
      user_fullname = var.guest_fullname
      user_name     = var.guest_username
      user_password = var.guest_password
    })
  }
}

source "vsphere-iso" "debian-11" {
  vm_name					      = var.vm_name
  # https://www.vmware.com/resources/compatibility/pdf/VMware_GOS_Compatibility_Guide.pdf
  guest_os_type			    = "debian11_64Guest"
  # https://kb.vmware.com/s/article/2007240
  vm_version				    = var.vm_version
  CPUs					        = var.vm_cpu_num
  RAM						        = var.vm_mem_size
  CPU_hot_plug			    = false
  RAM_hot_plug			    = true
  firmware				      = "efi"
  disk_controller_type	= ["nvme"]
  usb_controller 			  = ["xhci"]
  network_adapters {
    network			  = var.network
    network_card	= "vmxnet3"
    passthrough		= true
  }
  storage {
    disk_size				      = var.vm_disk_size
    disk_thin_provisioned	= true
  }
  remove_cdrom	        = true
  boot_order	        	= "cdrom,disk"
  boot_command	        = [
    "c<wait>",
    "linux /install.amd/vmlinuz ",
    "auto url=http://{{ .HTTPIP }}:{{ .HTTPPort }}/preseed.cfg ",
    "priority=high ",
    "locale=en_GB.UTF-8 ",
    "keymap=gb ",
    "hostname=${var.vm_name} ",
    "domain=${var.domain} ",
    "---<enter>",
    "initrd /install.amd/initrd.gz<enter>",
    "boot<enter>"
  ]
  vcenter_server		    = var.vcenter_server
  username			        = var.vcenter_username
  password			        = var.vcenter_password
  insecure_connection	  = true
  datacenter			      = var.datacenter
  datastore			        = var.datastore
  folder				        = var.folder
  host				          = var.host
  iso_checksum		      = "${var.iso_checksum_type}:${var.iso_checksum}"
  iso_url				        = var.iso_url
  ssh_username		      = var.guest_username
  ssh_password		      = var.guest_password
  http_content          = local.preseed_config
  convert_to_template	  = true
}

build {
  name 	= "template"
  sources = ["source.vsphere-iso.debian-11"]
 # provisioner "ansible" {
 #   playbook_file           = "../../ansible/debian-template.yml"
 #   use_proxy               = false
 #   max_retries             = 3
 #   inventory_file_template = "{{ .HostAlias }} ansible_host={{ .Host }} ansible_user={{ .User }} ansible_password={{ .Password }} ansible_become_password={{ .Password }} ansible_ssh_common_args='-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PubkeyAuthentication=no'"
 #   ansible_env_vars        = ["ANSIBLE_CONFIG=../../ansible/ansible.cfg"]
 # }
}

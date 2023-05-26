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

source "vsphere-iso" "debian_11" {
  vcenter_server    = var.vsphere_server
  username          = var.vsphere_user
  password          = var.vsphere_password
  datacenter        = var.datacenter
  datastore         = var.datastore
  cluster           = var.cluster
  insecure_connection  = true

  vm_name = var.vm_name
  guest_os_type = var.guest_os_version

  ssh_username = var.guest_username
  ssh_password = var.guest_password
  http_content = local.preseed_config

  CPUs         = var.vm_cpu_num
  RAM          = var.vm_mem_size
  RAM_reserve_all = true

  disk_controller_type =  ["lsilogic-sas"]
  storage {
    disk_size = var.vm_disk_size
    disk_thin_provisioned = true
  }

  iso_checksum		      = "${var.iso_checksum_type}:${var.iso_checksum}"
  iso_url				        = var.iso_url

  network_adapters {
    network =  var.network_name
    network_card = "vmxnet3"
  }

  boot_command = [
        "<esc><wait>",
        "install <wait>",
        "auto url=http://{{ .HTTPIP }}:{{ .HTTPPort }}/preseed.cfg ",
        " auto-install/enable=true ",
        " locale=en_US.UTF-8 <wait>",
        " priority=critical",
        "<enter><wait>"
  ]
}

build {
  sources  = [
    "source.vsphere-iso.debian_11"
  ]

  // provisioner "shell-local" {
  //   inline  = ["echo the address is: $PACKER_HTTP_ADDR and build name is: $PACKER_BUILD_NAME"]
  // }
  
  provisioner "ansible" {
    playbook_file           = "/home/hyoga/code/boilerplates/ansible/playbooks/packer.yaml"
    use_proxy               = false
    max_retries             = 3
    inventory_file_template = "{{ .HostAlias }} ansible_host={{ .Host }} ansible_user={{ .User }} ansible_password={{ .Password }} ansible_become_password={{ .Password }} ansible_ssh_common_args='-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PubkeyAuthentication=no'"
    ansible_env_vars        = ["ANSIBLE_CONFIG=/home/hyoga/code/boilerplates/ansible/ansible.cfg"]
  }
}

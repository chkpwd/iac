resource "proxmox_virtual_environment_file" "common_cloud_init" {
  content_type = "snippets"
  datastore_id = "local"
  node_name    = var.node

  source_raw {
    data      = <<-EOF
    #cloud-config
    timezone: America/New_York
    ssh_import_id: ["gh:chkpwd"]
    system_info:
      default_user:
        name: chkpwd
        groups: ["sudo"]
        shell: /bin/bash
        sudo: ALL=(ALL) NOPASSWD:ALL
    package_update: true
    packages: ["qemu-guest-agent"]
    runcmd: ["systemctl enable --now qemu-guest-agent"]
    EOF
    file_name = "user-data-cloud-config.yaml"
  }
}

resource "proxmox_virtual_environment_file" "meta_data" {
  for_each = var.nodes_cfg

  content_type = "snippets"
  datastore_id = "local"
  node_name    = var.node

  source_raw {
    data = templatefile("${path.root}/meta-data.tftpl", {
      hostname = each.value.name
    })
    file_name = "${each.key}-meta-data.yaml"
  }
}

resource "proxmox_virtual_environment_file" "common_cloud_init" {
  content_type = "snippets"
  datastore_id = "nas"
  node_name    = var.node

  source_raw {
    data = <<-EOF
    #cloud-config
    timezone: America/New_York
    preserve_hostname: false
    ssh_import_id: ["gh:chkpwd"]
    users:
      - default
      - name: chkpwd
        groups:
          - sudo
        shell: /bin/bash
        sudo: ALL=(ALL) NOPASSWD:ALL
    package_update: true
    packages:
      - qemu-guest-agent
    runcmd:
      - systemctl enable --now qemu-guest-agent
    EOF

    file_name = "user-data-cloud-config.yaml"
  }
}

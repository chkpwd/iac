resource "proxmox_virtual_environment_file" "common_cloud_init" {
  content_type = "snippets"
  datastore_id = "nas"
  node_name    = var.node

  source_raw {
    data = <<-EOF
    #cloud-config
    timezone: America/New_York
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

resource "proxmox_virtual_environment_file" "common_network" {
  content_type = "snippets"
  datastore_id = "nas"
  node_name    = var.node

  source_raw {
    data = <<-EOF
    #cloud-config
    network:
      version: 2
      renderer: networkd
      ethernets:
        enp1s0:
          mtu: 9000
          addresses:
            - 10.10.0.6/24
          dhcp4: true
          dhcp4-overrides:
            use-dns: true
            use-ntp: true
            send-hostname: true
            use-routes: false
            use-domains: true
          accept-ra: false
    EOF

    file_name = "network.yaml"
  }
}

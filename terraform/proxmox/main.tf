resource "proxmox_virtual_environment_cluster_options" "options" {
  language    = "en"
  keyboard    = "en-us"
  email_from  = "proxmox@chkpwd.com"
  max_workers = 5
}

resource "proxmox_virtual_environment_hardware_mapping_pci" "titan-x" {
  name = "titan-x"
  map = [
    {
      id           = "10de:17c2"
      iommu_group  = 47
      node         = var.node
      path         = "0000:44:00.0"
      subsystem_id = "3842:2992"
    },
  ]
  mediated_devices = false
}

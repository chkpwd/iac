module "horizon" {
  source                    = "../modules/vsphere"
  os_type                   = "linux"
  vm_name                   = "horizon"
  vm_cpu                    = 2
  vm_ram                    = 4096
  vm_template               = "deb-x11-template"
  vm_network                = "LAN"
  vm_dns                    = var.vm_dns
  vm_public_key             = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBK2VnKgOX7i1ISETheqjAO3/xo6D9n7QbWyfDAPsXwa hyoga@lifeline"
}

module "stable-diffusion" {
  source                    = "../modules/vsphere"
  os_type                   = "linux"
  vm_name                   = "stable-diffusion"
  vm_cpu                    = 4
  secondary_disks           = false
  vm_pri_disk_size          = 48 
  #vm_sec_disk_size          = 48
  vm_ram                    = 10240
  vm_network                = "Public"
  vm_template               = "deb-x11-template"
  vm_dns                    = var.vm_dns
  vm_public_key             = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBK2VnKgOX7i1ISETheqjAO3/xo6D9n7QbWyfDAPsXwa hyoga@lifeline"
}

module "crypto" {
  source                    = "../modules/vsphere"
  os_type                   = "linux"
  vm_name                   = "crypto"
  vm_cpu                    = 4
  vm_pri_disk_size          = "48"
  vm_ram                    = 4096
  vm_network                = "LAN"
  vm_template               = "deb-x11-template"
  vm_dns                    = var.vm_dns
  vm_public_key             = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBK2VnKgOX7i1ISETheqjAO3/xo6D9n7QbWyfDAPsXwa hyoga@lifeline"
}

module "mirage" {
  source                    = "../modules/vsphere"
  os_type                   = "linux"
  vm_name                   = "mirage"
  vm_cpu                    = 4
  vm_ram                    = 8192
  vm_network                = "Media"
  vm_template               = "deb-x11-template"
  vm_dns                    = var.vm_dns
  vm_public_key             = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBK2VnKgOX7i1ISETheqjAO3/xo6D9n7QbWyfDAPsXwa hyoga@lifeline"
}

module "homeassistant" {
  source                    = "../modules/vsphere"
  os_type                   = "linux"
  vm_name                   = "valkyrie"
  vm_cpu                    = 2
  vm_ram                    = 2048
  vm_network                = "IoT"
  vm_template               = "deb-x11-template"
  vm_dns                    = var.vm_dns
  vm_public_key             = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBK2VnKgOX7i1ISETheqjAO3/xo6D9n7QbWyfDAPsXwa crypto"
}

module "bloodhound" {
  source                    = "../modules/vsphere"
  count                     = 1
  os_type                   = "windows"
  instance_count            = 1
  vm_name                   = "bloodhound"
  vm_cpu                    = 2
  vm_ram                    = 8192
  vm_pri_disk_size          = 48 
  vm_network                = "LAN"
  vm_template               = "WinSrv22-template-DE"
  vm_public_key             = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBK2VnKgOX7i1ISETheqjAO3/xo6D9n7QbWyfDAPsXwa crypto"
}
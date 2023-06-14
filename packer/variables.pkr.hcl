variable "vcenter_datacenter" {
  default = "The Outlands"
}
variable "vcenter_server" {
    description = "vCenter server to build the VM on"
    default = "ronin.local.chkpwd.com"
}
variable "vcenter_username" {
    description = "Username to authenticate to vCenter"
    default = "administrator@vsphere.local.chkpwd.com"
}
variable "vcenter_password" {
    description = "Password to authenticate to vCenter"
    default     = ""
}
variable "vcenter_cluster" {
  default = "Eduardo"
}
variable "vcenter_host" {
  default = "octane.local.chkpwd.com"
}
variable "vcenter_datastore" {
  default = "nvme-30A"
}
variable "vcenter_folder" {
    description = "The vcenter folder to store the template"
    default = "Templates"
}
variable "connection_username" {
    default = "Administrator"
}
variable "connection_password" {
    default = "Unattendvm1"
}
variable "vm_hardware_version" {
    default = "15"
}
variable "iso_checksum" {}
variable "os_version" {
  default = ""
}
variable "os_iso_path" {
  default = ""
}
variable "guest_os_type" {}
variable "root_disk_size" {
    default = 48000
}
variable "nic_type" {
    default = "vmxnet3"
}
variable "network_name" { }
variable "num_cores" {
    default = 1
}
variable "mem_size" {
    default = 1024
}
variable "os_family" {
    description = "OS Family builds the paths needed for packer"
    default = ""
}
variable "os_iso_url" {
    description = "The download url for the ISO"
    default = ""
}
variable "boot_command" {
  default = ""
} #TODO: Figure out a better way to handle this
variable "iso_checksum_type" {}
variable "hostname" {}
variable "domain" {}
variable "machine_name" {}
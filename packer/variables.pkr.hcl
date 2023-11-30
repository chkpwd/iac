variable "vcenter_datacenter" {
  description = "vCenter datacenter to build the VM in"
  type        = string
  default     = "The Outlands"
}
variable "vcenter_server" {
  description = "vCenter server to build the VM on"
  default     = "vcenter.local.chkpwd.com"
}
variable "vcenter_username" {
  description = "Username to authenticate to vCenter"
  default     = "administrator@vsphere.local.chkpwd.com"
}
variable "vcenter_password" {
  description = "Password to authenticate to vCenter"
  type        = string
}
variable "vcenter_cluster" {
  default = "Eduardo"
  type    = string
}
variable "vcenter_host" {
  default = "octane.local.chkpwd.com"
  type    = string
}
variable "vcenter_datastore" {
  default = "NVME-30A"
  type    = string
}
variable "vcenter_folder" {
  description = "The vcenter folder to store the template"
  default     = "cattle/templates"
}
variable "connection_username" {
  default = "administrator"
  type    = string
}
variable "connection_password" {
  default = "Unattendvm1"
  type    = string
}
variable "vm_hardware_version" {
  default = "15"
  type    = string
}
variable "iso_checksum" {
  type    = string
}
variable "os_version" {
  type    = string
}
variable "os_iso_path" {
  type    = string
}
variable "guest_os_type" {
  type    = string
}
variable "vhd_controller_type" {
  type    = list(string)
}
variable "root_disk_size" {
  default = 48000
  type    = number
}
variable "nic_type" {
  default = "vmxnet3"
}
variable "network_name" {
  default = "LAN"
}
variable "num_cores" {
  default = 8
}
variable "mem_size" {
  default = 1024 * 8
  type    = number
}
variable "os_family" {
  description = "OS Family builds the paths needed for packer"
  type    = string
}
variable "os_iso_url" {
  description = "The download url for the ISO"
  default = ""
  type    = string
}
variable "boot_command" {
  description = "Series of commands to execute during boot"
  default = []
  type    = list(string)
}
variable "iso_checksum_type" {
  default = ""
  type = string
}
variable "hostname" {
  default = ""
  type = string
}
variable "domain" {
  default = ""
  type    = string
}
variable "machine_name" {
  default = ""
  type    = string
}
variable "preseed" {
  description = "The preseed file to use"
  default     = ""
  type        = string
}
variable "enable_tpm"  {
  default = "false"
  type    = bool
}
variable "listen_address" {
  default = ""
  type    = string
}

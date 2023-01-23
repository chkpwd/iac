variable "vsphere_server" {
  type    = string
}

variable "vsphere_user" {
  type    = string
}

variable "vsphere_password" {
  type    = string
}

variable "datacenter" {
  type    = string
}

variable "cluster" {
  type    = string
}

variable "datastore" {
  type    = string
}

variable "network_name" {
  type    = string
}

variable "iso_url" {
	type    = string
}

variable "iso_checksum" {
	type    = string
}

variable "iso_checksum_type" {
	type    = string
}

variable "guest_fullname" {
  type    = string
}

variable "guest_username" {
  type    = string
}

variable "guest_password" {
  type    = string
}

variable "guest_hostname" {
  type    = string
}

variable "vm_cpu_num" {
	type    = string
	default = ""
}

variable "vm_disk_size" {
	type    = string
}

variable "vm_mem_size" {
	type    = string
}
variable "vm_name" {
	type    = string
}
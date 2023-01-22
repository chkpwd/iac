variable "vsphere_server" {
  type    = string
  default = ""
}

variable "vsphere_user" {
  type    = string
  default = ""
}

variable "vsphere_password" {
  type    = string
  default = ""
}

variable "datacenter" {
  type    = string
  default = ""
}

variable "cluster" {
  type    = string
  default = ""
}

variable "datastore" {
  type    = string
  default = ""
}

variable "network_name" {
  type    = string
  default = ""
}

variable "iso_url" {
	type    = string
	default = ""
}

variable "iso_checksum" {
	type    = string
	default = ""
}

variable "iso_checksum_type" {
	type    = string
	default = ""
}

variable "guest_fullname" {
  type    = string
  default = ""
}

variable "guest_ssh_username" {
  type    = string
  default = ""
}

variable "guest_ssh_password" {
  type    = string
  default = ""
}

variable "guest_username" {
  type    = string
  default = ""
}

variable "guest_password" {
  type    = string
  default = ""
}

variable "guest_hostname" {
  type    = string
  default = ""
}

variable "vm_cpu_num" {
	type    = string
	default = ""
}

variable "vm_disk_size" {
	type    = string
	default = ""
}

variable "vm_mem_size" {
	type    = string
	default = ""
}
variable "vm_name" {
	type    = string
	default = ""
}

variable "vm_version" {
	type    = string
	default = ""
}
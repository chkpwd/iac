variable "datacenter" {
	type    = string
	default = ""
}

variable "datastore" {
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

variable "iso_url" {
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

variable "domain" {
	type    = string
	default = ""
}

variable "folder" {
	type    = string
	default = ""
}

variable "host" {
	type    = string
	default = ""
}

variable "hostname" {
	type    = string
	default = ""
}

variable "network" {
	type    = string
	default = ""
}

variable "guest_password" {
	type    = string
	default = ""
	sensitive = true
}

variable "guest_username" {
	type    = string
	default = ""
}

variable "guest_fullname" {
	type    = string
	default = ""
}

variable "vcenter_password" {
	type    = string
	default = ""
	sensitive = true
}

variable "vcenter_server" {
	type    = string
	default = ""
}

variable "vcenter_username" {
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
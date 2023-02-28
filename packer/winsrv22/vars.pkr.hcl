variable "datacenter" {
	type    = string
	default = ""
}

variable "datastore" {
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

variable "winrm_username" {
	type    = string
	default = ""
}

variable "winrm_password" {
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

variable "vcenter_password" {
	type    = string
	default = ""
	sensitive = true
}

variable "vm_cpu_num_core" {
	type    = string
	default = ""
}

variable "vm_mem_size_core" {
	type    = string
	default = ""
}

variable "vm_disk_size_core" {
	type    = string
	default = ""
}

variable "vm_cpu_num_gui" {
	type    = string
	default = ""
}

variable "vm_mem_size_gui" {
	type    = string
	default = ""
}

variable "vm_disk_size_gui" {
	type    = string
	default = ""
}

variable "iso_path" {
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

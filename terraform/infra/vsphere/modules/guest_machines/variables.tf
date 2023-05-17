variable "vsphere_vcenter" {
  description = "vCenter server FQDN or IP"
  default = "172.16.16.6"
}

variable "vsphere_unverified_ssl" {
  description = "Is the vCenter using a self signed certificate (true/false)"
  default = "true"
}

variable "vsphere_datacenter" {
  description = "vSphere datacenter"
  default = "The Outlands"
}

variable "vsphere_cluster" {
  description = "vSphere cluster"
  default     = "Eduardo"
}

#=========================#
# vSphere virtual machine #
#=========================#

variable "vm_datastore" {
  description = "Datastore used for the vSphere virtual machines"
  default = "nvme-30A"
}

variable "vm_network" {
  description = "Network used for the vSphere virtual machines"
  default = "LAN"
}

variable "vm_template" {
  description = "Template used to create the vSphere virtual machines"
}

variable "vm_linked_clone" {
  description = "Use linked clone to create the vSphere virtual machine from the template (true/false). If you would like to use the linked clone feature, your template need to have one and only one snapshot"
  default = "false"
}

variable "vm_ip" {
  description = "Ip used for the vSphere virtual machine"
  default = ""
}

variable "vm_netmask" {
  description = "Netmask used for the vSphere virtual machine (example: 24)"
  default = ""
}

variable "vm_gateway" {
  description = "Gateway for the vSphere virtual machine"
  default = ""
}

variable "vm_dns" {
  description = "DNS for the vSphere virtual machine"
  default = ""
}

variable "vm_domain" {
  description = "Domain for the vSphere virtual machine"
  default = ""
}

variable "dns_suffix" {
  type = list
  description = "Domain search list"
  default = []
  #default = ["typhon.tech"]
}

variable "vm_name" {
  description = "The name of the vSphere virtual machines and the hostname of the machine"
}

variable "ssh_username" {
  description = "ssh user for the guest"
  default = "hyoga"
}

variable "vm_public_key" {
  description = "Public SSH Key for VMs"
  default = ""
}

variable "os_type" {
  description = "Set the OS type"
  default = ""
}

variable "instance_count" {
  description = "The number of vSphere virtual machines"
  type = number
  default = 1
}

variable "folder_id" {
  type    = string
  default = ""
}

variable "spec" {
  type = object({
    cpu       = number
    memory    = number
    disk_size = number
    additional_network = optional(list(object({
      network = string
    })))
    additional_disks = optional(list(object({
      size = number
    })))
  })
}
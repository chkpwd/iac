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
  default = "datastore1"
}

variable "vm_network" {
  description = "Network used for the vSphere virtual machines"
  default = "LAN"
}

variable "domain" {
  description = "Domain for the vSphere virtual machine"
  default = "local.chkpwd.com"
}

variable "vm_name" {
  description = "The name of the vSphere virtual machines and the hostname of the machine"
}

variable "remote_ovf_url" {
  default = "https://github.com/siderolabs/talos/releases/download/v1.4.8/vmware-amd64.ova"
}

variable "spec" {
  type = object({
    cpu       = number
    memory    = number
  })
}

variable "network_spec" {
  type = object({
    network_id      = optional(string)
  })
}
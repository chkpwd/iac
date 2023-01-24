#====================#
# vCenter connection #
#====================#

# vSphere username used to deploy the infrastructure #
variable "vsphere_user" {
    description = "vSphere user"
    sensitive = true
} 

# vSphere password used to deploy the infrastructure #
variable "vsphere_password" {
    description = "vSphere password"
    sensitive = true
} 

variable "vsphere_vcenter" {
  description = "vCenter server FQDN or IP"
  default = "172.16.16.4"
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
  default = "VM Network"
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
}

variable "vm_netmask" {
  description = "Netmask used for the vSphere virtual machine (example: 24)"
}

variable "vm_gateway" {
  description = "Gateway for the vSphere virtual machine"
}

variable "vm_dns" {
  description = "DNS for the vSphere virtual machine"
}

variable "vm_domain" {
  description = "Domain for the vSphere virtual machine"
  default = "typhon.tech"
}

variable "vm_cpu" {
  description = "Number of vCPU for the vSphere virtual machines"
}

variable "vm_ram" {
  description = "Amount of RAM for the vSphere virtual machines (example: 2048)"
}

variable "vm_name" {
  description = "The name of the vSphere virtual machines and the hostname of the machine"
}

variable "vm_public_key" {
  description = "The name of the vSphere virtual machines and the hostname of the machine"
  default = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICsJocZS/OZ/4ZrLAxFOppiVMTym5oDkfHiir3YFg8mQ endeavourOS"
}

variable "ssh_username" {
  description = "ssh user for the guest"
  default = "hyoga"
}
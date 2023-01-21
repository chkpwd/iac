variable "vm_count" {
  description = "Specific numerical count for the VMs"
}
variable "ssh_key" {
  description = "The public key to use for the cluster"
  sensitive = true
}
variable "node" {
  description = "First Proxmox Node"
  default = "octane"
}
variable "api_url" {
  # url is the hostname (FQDN if you have one) for the proxmox host you'd like to connect to to issue the commands. my proxmox host is 'prox-1u'. Add /api2/json at the end for the API
  description = "url for proxmox cluster"
  sensitive = true
}
variable "token_id" {
  # api token id is in the form of: <username>@pam!<tokenId>
  description = "Token ID for the cluster"
  sensitive = true
}
variable "token_secret" {
  # this is the full secret wrapped in quotes. 
  description = "Token secret for the proxmox cluster" 
  sensitive = true
}
variable "vsphere_user" {
  description = "vSphere user"
  sensitive = true
}
variable "vsphere_password" {
  description = "vSphere password"
  sensitive = true
}
variable "vsphere_server_name" {
  description = "vSphere name of the server"
  sensitive = true
}
variable "template_name" {
  description = "Template for the container to clone"
  default = "debian-x11-cloud-drive"
}
variable "vm_user" {
  description = "The username for the current template"
  default = "hyoga"
}
variable "ip_address" {
  description = "IPv4 Address for the VMs"
}
variable "gateway" {
  description = "Set the gateway for the interface"
}
variable "bridge" {
  description = "Linux Bridge for the VM"
}
variable "disk_size" {
  description = "Size of the VM Disk"
  default = 32
}
variable "cpu_count" {
  description = "Core count for the VM"
  default = 1
}
variable "ram_size" {
  description = "RAM Size for the VM"
  default = 1024
}
variable "storage_location" {
  description = "Storage location for the VM"
  default = "Arenas"
}
variable "vlan_tag" {
  description = "VLAN tagging for the nic on the VM"
}
variable "vm_name" {
  description = "Name/Hostname of the VM"
  default = "debian-x11-cloud-drive"
}
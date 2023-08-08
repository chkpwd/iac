#====================#
# vCenter connection #
#====================#

variable "vsphere_vcenter" {
  description = "vCenter server FQDN or IP"
  default = "ronin.local.chkpwd.com"
  type        = string
}

variable "vsphere_unverified_ssl" {
  description = "Is the vCenter using a self signed certificate (true/false)"
  default = "true"
}

variable "vsphere_datacenter" {
  description = "vSphere datacenter"
  default = "The Outlands"
}
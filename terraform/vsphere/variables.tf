#====================#
# vCenter connection #
#====================#
variable "domain" {
  description = "Domain name"
  default = "local.chkpwd.com"
}

variable "vsphere_unverified_ssl" {
  description = "Is the vCenter using a self signed certificate (true/false)"
  default = "true"
}

variable "vsphere_datacenter" {
  description = "vSphere datacenter"
  default = "The Outlands"
}
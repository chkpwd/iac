#====================#
# vCenter connection #
#====================#

variable "vsphere_datacenter" {
  description = "vSphere datacenter"
  default = "The Outlands"
}
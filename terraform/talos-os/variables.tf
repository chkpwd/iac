variable "vsphere_server" {
  description = "vCenter server FQDN or IP"
  default = "ronin.local.chkpwd.com"
  type        = string
}

variable "vsphere_unverified_ssl" {
  default = "true"
}

variable "vsphere_datacenter" {
  description = "vSphere datacenter"
  default = "The Outlands"
}

variable "vsphere_compute_cluster" {
  description = "A name to provide for the Talos cluster"
  default     = "chkpwd"
  type        = string
}

variable "vsphere_datastore" {
  default = "NVME-30A"
}

variable "vsphere_network" {
  default = "Lab"
}

variable "vsphere_folder" {
  default = "kubernetes"
}

variable "vsphere_talos_template" {
  default = "templates/talos-1.3.5-amd64"
}

variable "prefix" {
  default = "tf-talos"
}

variable "controller_count" {
  type    = number
  default = 1
  validation {
    condition     = var.controller_count >= 1
    error_message = "Must be 1 or more."
  }
}

variable "worker_count" {
  type    = number
  default = 1
  validation {
    condition     = var.worker_count >= 1
    error_message = "Must be 1 or more."
  }
}

variable "cluster_name" {
  type    = string
  default = "example"
}
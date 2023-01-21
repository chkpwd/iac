terraform {
  required_providers {
    proxmox = {
      source = "telmate/proxmox"
      version = "2.9.11"
    }
    vsphere = {
      source = "hashicorp/vsphere"
      version = "2.2.0"
    }
  }
}

provider "vsphere" {
  user           = var.vsphere_user
  password       = var.vsphere_password
  vsphere_server = var.vsphere_server_name
  allow_unverified_ssl = true

  data "vsphere_datacenter" "dc" {
    name = var.vsphere-datacenter
  }

  data "vsphere_datastore" "datastore" {
    name          = var.vm-datastore
    datacenter_id = data.vsphere_datacenter.dc.id
  }

  data "vsphere_compute_cluster" "cluster" {
    name          = var.vsphere-cluster
    datacenter_id = data.vsphere_datacenter.dc.id
  }

  data "vsphere_network" "network" {
    name          = var.vm-network
    datacenter_id = data.vsphere_datacenter.dc.id
  }
}


provider "proxmox" {

  # url is the hostname (FQDN if you have one) for the proxmox host you'd like to connect to to issue the commands. my proxmox host is 'prox-1u'. Add /api2/json at the end for the API
  pm_api_url = var.api_url

  # api token id is in the form of: <username>@pam!<tokenId>
  pm_api_token_id = var.token_id

  # this is the full secret wrapped in quotes. don't worry, I've already deleted this from my proxmox cluster by the time you read this post
  pm_api_token_secret = var.token_secret

  # leave tls_insecure set to true unless you have your proxmox SSL certificate situation fully sorted out (if you do, you will know)
  pm_tls_insecure = true

  # Allowed simultaneous Proxmox processes (e.g. creating resources)
  pm_parallel = 5

}

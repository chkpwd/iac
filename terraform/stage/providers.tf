#===============================================================================
# vSphere Provider
#===============================================================================

terraform {
  required_providers {
    vsphere = {
      source = "hashicorp/vsphere"
      version = "2.2.0"
    }
    vultr = {
      source = "vultr/vultr"
      version = "2.12.0"
    }
    proxmox = {
      source = "telmate/proxmox"
      version = "2.9.11"
    }
    aws = {
      source = "hashicorp/aws"
      version = "4.55.0"
    }
  }
}

# Configure the vSphere Provider
provider "vsphere" {
  vsphere_server = "${var.vsphere_vcenter}"
  user           = "${var.vsphere_user}"
  password       = "${var.vsphere_password}"

  allow_unverified_ssl = "${var.vsphere_unverified_ssl}"
}

# Configure the Vultr Provider
provider "vultr" {
  api_key = "${var.vultr_api_key}"
  rate_limit = 100
  retry_limit = 3
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


variable "oci_availability_domain_number" {
  type = number
}

variable "instance_spec" {
  type = object({
    name      = string
    cpus      = number
    memory_gb = number
    disk_size = optional(number, 50) # Default min size
    shape     = string
    image_id  = string
    network   = object({
      subnet_id                 = string
      vnic_label                = optional(string, "Primaryvnic")
      hostname                  = optional(string)
      assign_public_ip          = optional(string, false)
      assign_private_dns_record = optional(string, false)
      private_ip                = optional(string)
    })
    ssh_authorized_keys = string
  })
}

variable "ssh_allowed_ips" {
  type = list(object({
    description = string
    ip = string
  }))
}
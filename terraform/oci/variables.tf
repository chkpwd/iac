variable "private_key_path" {
  default = "~/.ssh/oci.pem"
  description = "Path to the Private Key for the OCI org"
}

variable "main_pub_key" {
  default = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILUG+qEDkI4NeBLLtyrSPfHhlhxjBwkdYGNECCX3JpLg oci"
}

# variable "availability_domain" {}

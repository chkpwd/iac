# variable "ssh_allowed_ips" {
#   type = list(object({
#     description = string
#     ip = string
#   }))
# }

variable "aws_region" {
  description = "AWS Region"
  type        = string
  default     = "us-east-1"
}

variable "availability_zone" {
  description = "Availability Zone"
  type        = string
  default     = "us-east-1a"
}

variable "network_configuration" {
  description = "Network configuration for VPC and public subnet"
  type = object({
    vpc_cidr            = string
    public_subnet_cidr  = string
  })
  default = {
    vpc_cidr            = "10.50.0.0/18"
    public_subnet_cidr  = "10.50.25.0/24"
  }
}

variable "security_group" {
  description = "Security group for VPC and public subnet"
  type = list(string) 
  default = []
}

variable "ssh_configuration" {
  type = object({
    public_key  = string
    private_key = string
    ssh_port    = number
  })
  default = {
    public_key  = "~/.ssh/aws.pub"
    private_key = "~/.ssh/aws"
    ssh_port    = 22
  }
}

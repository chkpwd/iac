variable "instance_spec" {
  type = object({
    name      = string
    ami       = string
    type      = string
    key_name  = string
  })
}

variable "vpc_security_groups" {
  type = list(string)
  default = []
}

variable "subnet_id" {
  type = string
  default = null
}

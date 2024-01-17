variable "name" {
  type = string
}

variable "group" {
  type = string
}

variable "app_values" {
  type = object({
    meta_publisher = optional(string)
    meta_description = optional(string)
    icon_url = optional(string)
  })
}

variable "access_group" {
  type = list(string)
}

variable "jwks_sources" {
  type    = list(string)
  default = []
}

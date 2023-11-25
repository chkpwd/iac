variable "name" {
  type = string
}

variable "group" {
  type = string
}

variable "proxy_values" {
  type = object({
    internal                          = string
    external                          = string
    mode                              = string
    skip_path_regex                   = optional(string)
    internal_host_ssl_validation      = optional(bool)
    jwks_sources                      = optional(list(string))
  })
  
  default = {
    internal                          = null
    external                          = null
    mode                              = "forward_single"
    skip_path_regex                   = null
    internal_host_ssl_validation      = true
    jwks_sources                      = []
  }
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

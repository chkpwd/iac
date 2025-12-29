variable "name" {
  type = string
}

variable "group" {
  type = string
}

variable "oauth2_values" {
  type = object({ # Optional type requires object
    client_id         = string
    provider_type     = optional(string)
    authorization_url = optional(string)
    access_token_url  = optional(string)
    consumer_key      = optional(string)
    consumer_secret   = optional(string)
    client_secret     = optional(string)
    client_type       = optional(string)
    property_mappings = optional(list(string))
    allowed_redirect_uris = list(object({
      matching_mode = string
      url           = string
    }))
  })
}

variable "app_values" {
  type = object({
    meta_publisher   = optional(string)
    meta_description = optional(string)
    icon_url         = optional(string)
  })
}

variable "access_group" {
  type = map(string)
}

# variable "jwks_sources" {
#   type    = list(string)
#   default = []
# }

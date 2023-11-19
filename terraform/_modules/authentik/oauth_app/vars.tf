variable "name" {
  type = string
}

variable "group" {
  type = string
}

variable "provider_type" {
  type = string
}

variable "authorization_url" {
  type = string
}

variable "access_token_url" {
  type = string
}

variable "consumer_key" {
  type = string
}

variable "consumer_secret" {
  type = string
}

variable "meta_publisher" {
  type    = string
  default = null
}

variable "icon_url" {
  type    = string
  default = null
}

variable "access_group" {
  type = list(string)
}

output "app_id" {
  value = authentik_application.app.id
}

variable "jwks_sources" {
  type    = list(string)
  default = []
}

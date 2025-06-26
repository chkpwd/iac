variable "node" {
  type    = string
  default = "pve-srv-01"
}

variable "domain" {
  type    = string
  default = "chkpwd.com"
}

variable "dns_servers" {
  type    = list(string)
  default = ["1.1.1.1", "1.0.0.1"]
}

variable "timezone" {
  type    = string
  default = "America/New_York"
}

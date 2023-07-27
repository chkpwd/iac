variable media_domain {
  type = string
  default = "local.chkpwd.com"
  description = "Media Host IP Address"
}

variable "ports" {
  type = map(string)
  default = {
    "sonarr"      = "8989"
    "prowlarr"    = "9696"
    "radarr"      = "7878"
    "sabnzbd"     = "8080"
    "qbittorrent" = "8080"
  }
  description = "Mapping of services to their respective ports"
}
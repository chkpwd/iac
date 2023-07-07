variable media_host_ip {
  type = string
  default = "172.16.10.20"
  description = "Media Host IP Address"
}

variable "ports" {
  type = map(string)
  default = {
    "sonarr"      = "8989"
    "prowlarr"    = "9696"
    "radarr"      = "7878"
    "sabnzbd"     = "8180"
    "qbittorrent" = "8280"
  }
  description = "Mapping of services to their respective ports"
}
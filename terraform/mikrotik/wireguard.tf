resource "routeros_interface_wireguard" "this" {
  name        = "wireguard"
  listen_port = "53834"
}

resource "routeros_interface_wireguard_peer" "phone" {
  interface       = routeros_interface_wireguard.this.name
  public_key      = "efACr1t5ujUxiwoX0kbl7HIC+rwm/Xj5gMGVL9RkKWo="
  allowed_address = ["${cidrhost("${routeros_ip_address.wireguard.network}/24", 2)}/32"]
  comment         = "iPhone"
}

resource "routeros_interface_wireguard_peer" "macbook" {
  interface       = routeros_interface_wireguard.this.name
  public_key      = "qEMC3PepvziglcPkU+expRKy4HwBHrYvRfWPUQnE9Es="
  allowed_address = ["${cidrhost("${routeros_ip_address.wireguard.network}/24", 3)}/32"]
  comment         = "macbook"
}

resource "routeros_interface_wireguard_peer" "gatus" {
  interface       = routeros_interface_wireguard.this.name
  public_key      = "Cwnm7KjWDhpjPXG/Bu3fEsHFNtrGnjXIDPMpm9m6pQI="
  allowed_address = ["${cidrhost("${routeros_ip_address.wireguard.network}/24", 4)}/32"]
  comment         = "gatus"
}

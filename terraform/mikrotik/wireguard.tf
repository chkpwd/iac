resource "routeros_interface_wireguard" "this" {
  name        = "wireguard"
  listen_port = "53834"
}

resource "routeros_interface_wireguard_peer" "phone" {
  interface       = routeros_interface_wireguard.this.name
  public_key      = "efACr1t5ujUxiwoX0kbl7HIC+rwm/Xj5gMGVL9RkKWo="
  allowed_address = ["10.6.6.2/32"]
  comment         = "iPhone"
}

resource "routeros_interface_wireguard_peer" "macbook" {
  interface       = routeros_interface_wireguard.this.name
  public_key      = "qEMC3PepvziglcPkU+expRKy4HwBHrYvRfWPUQnE9Es="
  allowed_address = ["10.6.6.3/32"]
  comment         = "macbook"
}

resource "routeros_wireguard_keys" "wgk" {
  number = 3
}

resource "routeros_interface_wireguard" "this" {
  name        = "wireguard"
  listen_port = "53834"
}

resource "routeros_interface_wireguard_peer" "phone" {
  interface       = routeros_interface_wireguard.this.name
  public_key      = routeros_wireguard_keys.wgk.keys[0].public
  private_key     = routeros_wireguard_keys.wgk.keys[0].private
  allowed_address = ["${cidrhost("${routeros_ip_address.wireguard.network}/24", 2)}/32"]
  comment         = "iphone"
}

resource "routeros_interface_wireguard_peer" "macbook" {
  interface       = routeros_interface_wireguard.this.name
  public_key      = routeros_wireguard_keys.wgk.keys[1].public
  private_key     = routeros_wireguard_keys.wgk.keys[1].private
  allowed_address = ["${cidrhost("${routeros_ip_address.wireguard.network}/24", 3)}/32"]
  comment         = "macbook"
}

resource "routeros_interface_wireguard_peer" "gatus" {
  interface       = routeros_interface_wireguard.this.name
  public_key      = routeros_wireguard_keys.wgk.keys[2].public
  private_key     = routeros_wireguard_keys.wgk.keys[2].private
  allowed_address = ["${cidrhost("${routeros_ip_address.wireguard.network}/24", 4)}/32"]
  comment         = "gatus"
}

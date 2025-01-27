data "unifi_ap_group" "main" {}

data "unifi_user_group" "main" {}

data "unifi_network" "lan" {
  name = "Default"
  site = var.site
}

resource "unifi_wlan" "lan" {
  name       = "Eiha"
  passphrase = data.external.bws_lookup.result["infra-network-secrets_unifi_wlan_lan_pwd"]
  security   = "wpapsk"

  # enable WPA2/WPA3 support
  wpa3_support    = true
  wpa3_transition = true
  pmf_mode        = "optional"

  network_id    = data.unifi_network.lan.id
  ap_group_ids  = [data.unifi_ap_group.main.id]
  user_group_id = data.unifi_user_group.main.id
}

resource "unifi_wlan" "guest" {
  name       = "Guest-Eiha"
  passphrase = data.external.bws_lookup.result["infra-network-secrets_unifi_wlan_guest_pwd"]
  security   = "wpapsk"

  # enable WPA2/WPA3 support
  wpa3_support    = true
  wpa3_transition = true
  pmf_mode        = "optional"

  network_id    = unifi_network.guest.id
  ap_group_ids  = [data.unifi_ap_group.main.id]
  user_group_id = data.unifi_user_group.main.id
}

resource "unifi_wlan" "iot" {
  name       = "IoT-Eiha"
  passphrase = data.external.bws_lookup.result["infra-network-secrets_unifi_wlan_iot_pwd"]
  security   = "wpapsk"

  # enable WPA2/WPA3 support
  wpa3_support    = true
  wpa3_transition = true
  pmf_mode        = "optional"

  network_id   = unifi_network.iot.id
  ap_group_ids = [data.unifi_ap_group.main.id]

  user_group_id = data.unifi_user_group.main.id
}

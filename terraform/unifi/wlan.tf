data "unifi_ap_group" "default" {}

data "unifi_user_group" "default" {}

data "unifi_network" "lan" {
  name = "Default"
  site = var.site
}

resource "unifi_wlan" "lan" {
  name       = "Eiha"
  passphrase = data.sops_file.unifi-secrets.data["unifi_wlan_lan_pwd"]
  security   = "wpapsk"

  # enable WPA2/WPA3 support
  wpa3_support    = true
  wpa3_transition = true
  pmf_mode        = "optional"

  network_id    = data.unifi_network.lan.id
  ap_group_ids  = [data.unifi_ap_group.default.id]
  user_group_id = data.unifi_user_group.default.id
}

resource "unifi_wlan" "iot" {
  name       = "IoT-Eiha"
  passphrase = data.sops_file.unifi-secrets.data["unifi_wlan_iot_pwd"]
  security   = "wpapsk"

  # enable WPA2/WPA3 support
  wpa3_support    = true
  wpa3_transition = true
  pmf_mode        = "optional"

  network_id    = unifi_network.iot.id
  ap_group_ids  = [data.unifi_ap_group.default.id]
  user_group_id = data.unifi_user_group.default.id
}

resource "unifi_wlan" "lab" {
  name       = "Lab-Eiha"
  passphrase = data.sops_file.unifi-secrets.data["unifi_wlan_lab_pwd"]
  security   = "wpapsk"

  # enable WPA2/WPA3 support
  wpa3_support    = true
  wpa3_transition = true
  pmf_mode        = "optional"

  network_id    = unifi_network.lab.id
  ap_group_ids  = [data.unifi_ap_group.default.id]
 
  user_group_id = data.unifi_user_group.default.id
}


resource "unifi_wlan" "media" {
  name       = "Media-Eiha"
  passphrase = data.sops_file.unifi-secrets.data["unifi_wlan_media_pwd"]
  security   = "wpapsk"

  # enable WPA2/WPA3 support
  wpa3_support    = true
  wpa3_transition = true
  pmf_mode        = "optional"

  network_id    = unifi_network.media.id
  ap_group_ids  = [data.unifi_ap_group.default.id]
  user_group_id = data.unifi_user_group.default.id
}
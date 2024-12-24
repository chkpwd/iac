resource "uptimerobot_monitor" "gatus" {
  friendly_name = "Gatus"
  type          = "http"
  url           = "https://gatus.chkpwd.com"
}

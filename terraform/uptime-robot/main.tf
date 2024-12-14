resource "uptimerobot_alert_contact" "slack" {
  friendly_name = "Discord"
  type          = "webhook"
  webhook_url   = data.external.bws_lookup.result["discord_alert_webhook"]
}

resource "uptimerobot_monitor" "gatus" {
  friendly_name = "Gatus"
  type          = "http"
  url           = "https://gatus.chkpwd.com"
}

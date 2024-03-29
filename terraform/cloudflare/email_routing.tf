resource "cloudflare_email_routing_settings" "settings" {
  enabled = true
  zone_id = data.external.bws_lookup.result["cloudflare-dns-secrets_zone_id"]
}

resource "cloudflare_email_routing_address" "catch_all_address" {
  account_id = data.external.bws_lookup.result["cloudflare-dns-secrets_account_id"]
  email      = data.external.bws_lookup.result["common-secrets_primary_email_address"]
}

resource "cloudflare_email_routing_catch_all" "catch_all" {
  zone_id = data.external.bws_lookup.result["cloudflare-dns-secrets_zone_id"]
  name    = "Gmail Catch All"
  enabled = true

  matcher {
    type = "all"
  }

  action {
    type  = "forward"
    value = ["${data.external.bws_lookup.result["common-secrets_primary_email_address"]}"]
  }
}

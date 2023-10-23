resource "cloudflare_email_routing_settings" "settings" {
  enabled = true
  zone_id = data.sops_file.cloudflare-secrets.data["cloudflare_zone_id"]
}

resource "cloudflare_email_routing_address" "catch_all_address" {
  account_id = data.sops_file.cloudflare-secrets.data["cloudflare_account_id"]
  email      = data.sops_file.cloudflare-secrets.data["gmail_address"]
}

resource "cloudflare_email_routing_catch_all" "catch_all" {
  zone_id = data.sops_file.cloudflare-secrets.data["cloudflare_zone_id"]
  name    = "Gmail Catch All"
  enabled = true

  matcher {
    type = "all"
  }

  action {
    type  = "forward"
    value = [ "${data.sops_file.cloudflare-secrets.data["gmail_address"]}" ]
  }
}

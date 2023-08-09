resource "cloudflare_record" "main" {
  name    = "chkpwd.com"
  proxied = true
  ttl     = 1
  type    = "A"
  value   = data.sops_file.cloudflare-secrets.data["public_address"]
  zone_id = data.sops_file.cloudflare-secrets.data["cloudflare_zone_id"]
}

resource "cloudflare_record" "www_main" {
  name    = "www"
  proxied = true
  ttl     = 1
  type    = "A"
  value   = data.sops_file.cloudflare-secrets.data["public_address"]
  zone_id = data.sops_file.cloudflare-secrets.data["cloudflare_zone_id"]
}

resource "cloudflare_record" "uptime" {
  name    = "uptime.chkpwd.com"
  proxied = true
  ttl     = 1
  type    = "A"
  value   = data.tfe_outputs.oci.values.ct-01-x86_public_ip
  zone_id = data.sops_file.cloudflare-secrets.data["cloudflare_zone_id"]
}

resource "cloudflare_record" "couchdb" {
  name    = "couchdb.chkpwd.com"
  proxied = true
  ttl     = 1
  type    = "A"
  value   = data.tfe_outputs.oci.values.ct-02-x86_public_ip
  zone_id = data.sops_file.cloudflare-secrets.data["cloudflare_zone_id"]
}

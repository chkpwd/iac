resource "cloudflare_record" "blog" {
  name    = "blog"
  proxied = true
  ttl     = 1
  type    = "CNAME"
  value   = "chkpwd.github.io"
  zone_id = data.external.bws_lookup.result["cloudflare-dns-secrets_zone_id"]
}

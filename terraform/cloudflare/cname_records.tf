resource "cloudflare_dns_record" "blog" {
  name    = "blog"
  proxied = true
  ttl     = 1
  type    = "CNAME"
  content = "chkpwd.github.io"
  zone_id = data.external.bws_lookup.result["cloudflare-dns-secrets_zone_id"]
}

resource "cloudflare_dns_record" "docs" {
  name    = "docs"
  proxied = true
  ttl     = 1
  type    = "CNAME"
  content = "chkpwd.github.io"
  zone_id = data.external.bws_lookup.result["cloudflare-dns-secrets_zone_id"]
}

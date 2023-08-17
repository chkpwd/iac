resource "cloudflare_record" "blog" {
  name    = "blog"
  proxied = true
  ttl     = 1
  type    = "CNAME"
  value   = "chkpwd.github.io"
  zone_id = data.sops_file.cloudflare-secrets.data["cloudflare_zone_id"]
}

resource "cloudflare_record" "github_txt" {
  name    = "_github-challenge-chkpwd-org.chkpwd.com"
  ttl     = 1
  type    = "TXT"
  value   = data.sops_file.cloudflare-secrets.data["git_txt_record_value"]
  zone_id = data.sops_file.cloudflare-secrets.data["cloudflare_zone_id"]
}

resource "cloudflare_record" "cloudflare_email_txt" {
  name    = "@"
  ttl     = 1
  type    = "TXT"
  value   = "v=spf1 include:_spf.mx.cloudflare.net ~all"
  proxied  = false
  comment  = "Terraform - SPF - email"
  zone_id = data.sops_file.cloudflare-secrets.data["cloudflare_zone_id"]
}
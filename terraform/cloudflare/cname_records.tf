resource "cloudflare_record" "overseerr" {
  name    = "overseerr"
  proxied = true
  ttl     = 1
  type    = "CNAME"
  value   = "chkpwd.com"
  zone_id = data.sops_file.cloudflare-secrets.data["cloudflare_zone_id"]
}

resource "cloudflare_record" "zipline_cname" {
  name    = "zipline"
  proxied = true
  ttl     = 1
  type    = "CNAME"
  value   = "chkpwd.com"
  zone_id = data.sops_file.cloudflare-secrets.data["cloudflare_zone_id"]
}

resource "cloudflare_record" "winxuu_cname" {
  name    = "winxuu"
  proxied = true
  ttl     = 1
  type    = "CNAME"
  value   = "chkpwd.com"
  zone_id = data.sops_file.cloudflare-secrets.data["cloudflare_zone_id"]
}

resource "cloudflare_record" "kavita_cname" {
  name    = "kavita"
  proxied = true
  ttl     = 1
  type    = "CNAME"
  value   = "chkpwd.com"
  zone_id = data.sops_file.cloudflare-secrets.data["cloudflare_zone_id"]
}

resource "cloudflare_record" "freshrss_cname" {
  name    = "rss"
  proxied = true
  ttl     = 1
  type    = "CNAME"
  value   = "chkpwd.com"
  zone_id = data.sops_file.cloudflare-secrets.data["cloudflare_zone_id"]
}

resource "cloudflare_record" "vaultwarden_cname" {
  name    = "vault"
  proxied = true
  ttl     = 1
  type    = "CNAME"
  value   = "chkpwd.com"
  zone_id = data.sops_file.cloudflare-secrets.data["cloudflare_zone_id"]
}

resource "cloudflare_record" "wizarr_cname" {
  name    = "wizarr"
  proxied = true
  ttl     = 1
  type    = "CNAME"
  value   = "chkpwd.com"
  zone_id = data.sops_file.cloudflare-secrets.data["cloudflare_zone_id"]
}

resource "cloudflare_record" "homeassistant_cname" {
  name    = "zeal"
  proxied = true
  ttl     = 1
  type    = "CNAME"
  value   = "chkpwd.com"
  zone_id = data.sops_file.cloudflare-secrets.data["cloudflare_zone_id"]
}

resource "cloudflare_record" "blog_cname" {
  name    = "blog"
  proxied = true
  ttl     = 1
  type    = "CNAME"
  value   = "chkpwd.github.io"
  zone_id = data.sops_file.cloudflare-secrets.data["cloudflare_zone_id"]
}

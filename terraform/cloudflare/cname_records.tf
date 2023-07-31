resource "cloudflare_record" "miniflux" {
  name    = "miniflux"
  proxied = true
  ttl     = 1
  type    = "CNAME"
  value   = "chkpwd.com"
  zone_id = data.sops_file.cloudflare-secrets.data["cloudflare_zone_id"]
}

resource "cloudflare_record" "overseerr" {
  name    = "overseerr"
  proxied = true
  ttl     = 1
  type    = "CNAME"
  value   = "chkpwd.com"
  zone_id = data.sops_file.cloudflare-secrets.data["cloudflare_zone_id"]
}

resource "cloudflare_record" "winxuu" {
  name    = "winxuu"
  proxied = true
  ttl     = 1
  type    = "CNAME"
  value   = "chkpwd.com"
  zone_id = data.sops_file.cloudflare-secrets.data["cloudflare_zone_id"]
}

resource "cloudflare_record" "kavita" {
  name    = "kavita"
  proxied = true
  ttl     = 1
  type    = "CNAME"
  value   = "chkpwd.com"
  zone_id = data.sops_file.cloudflare-secrets.data["cloudflare_zone_id"]
}

resource "cloudflare_record" "freshrss" {
  name    = "freshrss"
  proxied = true
  ttl     = 1
  type    = "CNAME"
  value   = "chkpwd.com"
  zone_id = data.sops_file.cloudflare-secrets.data["cloudflare_zone_id"]
}

resource "cloudflare_record" "vaultwarden" {
  name    = "vault"
  proxied = true
  ttl     = 1
  type    = "CNAME"
  value   = "chkpwd.com"
  zone_id = data.sops_file.cloudflare-secrets.data["cloudflare_zone_id"]
}

resource "cloudflare_record" "wizarr" {
  name    = "wizarr"
  proxied = true
  ttl     = 1
  type    = "CNAME"
  value   = "chkpwd.com"
  zone_id = data.sops_file.cloudflare-secrets.data["cloudflare_zone_id"]
}

resource "cloudflare_record" "homeassistant" {
  name    = "zeal"
  proxied = true
  ttl     = 1
  type    = "CNAME"
  value   = "chkpwd.com"
  zone_id = data.sops_file.cloudflare-secrets.data["cloudflare_zone_id"]
}

resource "cloudflare_record" "blog" {
  name    = "blog"
  proxied = true
  ttl     = 1
  type    = "CNAME"
  value   = "chkpwd.github.io"
  zone_id = data.sops_file.cloudflare-secrets.data["cloudflare_zone_id"]
}

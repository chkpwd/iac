resource "cloudflare_zone_settings_override" "settings" {
  zone_id = data.sops_file.cloudflare-secrets.data["cloudflare_zone_id"]
  settings {
    # ssl-tls
    ssl = "full"

    # ssl-tls | edge-certificates
    always_use_https         = "on"
    min_tls_version          = "1.0"
    opportunistic_encryption = "on"
    tls_1_3                  = "zrt"
    automatic_https_rewrites = "on"
    #universal_ssl            = "on"

    # Firewall Settings
    browser_check  = "on"
    challenge_ttl  = 1800
    privacy_pass   = "on"
    security_level = "medium"

    # Optimization for speed
    brotli = "on"

    minify {
      css  = "on"
      js   = "on"
      html = "on"
    }

    rocket_loader = "on"

    # Caching Configuration
    always_online    = "off"
    development_mode = "off"

    # Network
    http3               = "on"
    zero_rtt            = "on"
    ipv6                = "on"
    websockets          = "on"
    opportunistic_onion = "on"
    pseudo_ipv4         = "off"
    ip_geolocation      = "on"

    # Content Protection
    email_obfuscation   = "on"
    server_side_exclude = "on"
    hotlink_protection  = "off"

    # Workers
    security_header {
      enabled = false
    }

  }
}
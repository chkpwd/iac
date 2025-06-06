resource "cloudflare_dns_record" "github_txt" {
  name    = "_github-challenge-chkpwd-org.chkpwd.com"
  ttl     = 1
  type    = "TXT"
  content = "\"${data.external.bws_lookup.result["cloud-github-secrets_git_txt_record"]}\""
  zone_id = data.external.bws_lookup.result["cloudflare-dns-secrets_zone_id"]
}

resource "cloudflare_dns_record" "aws_instance_proxy_txt" {
  name    = "@"
  ttl     = 1
  type    = "TXT"
  content = "\"${data.external.bws_lookup.result["cloud-aws-proxy-secrets_swag_txt_record"]}\""
  proxied = false
  comment = "Terraform - AWS Instance Proxy - TXT Record"
  zone_id = data.external.bws_lookup.result["cloudflare-dns-secrets_zone_id"]
}

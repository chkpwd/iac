data "tfe_outputs" "aws" {
  organization = "chkpwd"
  workspace    = "aws"
}

# data "cloudflare_email_routing_settings" "settings" {
#   zone_id = data.external.bws_lookup.result["cloudflare-dns-secrets_zone_id"]
# }


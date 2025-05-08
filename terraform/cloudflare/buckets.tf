# resource "cloudflare_r2_bucket" "pg-cluster" {
#   account_id    = data.external.bws_lookup.result["cloudflare-dns-secrets_account_id"]
#   name          = "pg-cluster-backups"
#   location      = "ENAM"
#   storage_class = "Standard"
# }

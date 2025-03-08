locals {
  buckets = [
    "postgresql",
    "volsync"
  ]
}

module "buckets" {
  source      = "../_modules/minio"
  for_each    = toset(local.buckets)
  bucket_name = each.key
  user_name   = minio_iam_user.main.name
  user_secret = data.external.bws_lookup.result["infra-minio-secrets_restic_user_password"]

  providers = {
    minio = minio
  }
}

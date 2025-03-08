terraform {
  required_version = "1.11.0"
  required_providers {
    minio = {
      source  = "aminueza/minio"
      version = "3.3.0"
    }
    external = {
      source  = "hashicorp/external"
      version = "~> 2"
    }
  }
}

data "external" "bws_lookup" {
  program = ["python3", "../bws_lookup.py"]
  query = {
    key = "infra-minio-secrets"
  }
}

provider "minio" {
  minio_server   = "nas-srv-01.local.chkpwd.com:9000"
  minio_user     = "minio"
  minio_password = data.external.bws_lookup.result["infra-minio-secrets_minio_user_password"]
}

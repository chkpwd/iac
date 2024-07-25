terraform {
  required_providers {
    backblaze = {
      source  = "Backblaze/b2"
      version = "0.8.12"
    }
  }
}

data "external" "bws_lookup" {
  program = ["python3", "../bws_lookup.py"]
  query = {
    key = "cloud-backblaze-secrets"
  }
}

provider "backblaze" {
  application_key_id = data.external.bws_lookup.result["cloud-backblaze-secrets_appid"]
  application_key    = data.external.bws_lookup.result["cloud-backblaze-secrets_appkey"]
}

terraform {
  required_version = "~> 1.12"
  required_providers {
    opnsense = {
      source  = "browningluke/opnsense"
      version = "0.16.1"
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
    key = "infra-network-secrets"
  }
}

provider "opnsense" {
  uri        = "http://10.0.10.1"
  api_key    = data.external.bws_lookup.result["infra-network-secrets_opnsense_api_key"]
  api_secret = data.external.bws_lookup.result["infra-network-secrets_opnsense_api_secret"]
}

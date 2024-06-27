terraform {
  required_providers {
    grafana = {
      source  = "grafana/grafana"
      version = ">= 1.28.2"
    }
  }
}

data "external" "bws_lookup" {
  program = ["python3", "../bws_lookup.py"]
  query = {
    key = "infra-monitoring-secrets"
  }
}

provider "grafana" {
  url  = "https://grafana.local.chkpwd.com"
  auth = data.external.bws_lookup.result["infra-monitoring-secrets_grafana_api_key"]
}

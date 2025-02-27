terraform {
  required_version = "1.10.5"
  required_providers {
    uptimerobot = {
      source = "bartekbp/uptimerobot"
      version = "0.10.0"
    }
    external = {
      source = "hashicorp/external"
      version = "~> 2"
    }
  }
}

data "external" "bws_lookup" {
  program = ["python3", "../bws_lookup.py"]
  query = {
    key = "infra-monitoring-secrets"
  }
}

provider "uptimerobot" {
  api_key = data.external.bws_lookup.result["infra-monitoring-secrets_uptime_robot_api_key"]
}

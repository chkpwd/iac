terraform {
  required_providers {
    uptimerobot = {
      source = "louy/uptimerobot"
      version = "0.5.1"
    }
  }
}

data "external" "bws_lookup" {
  program = ["python3", "../bws_lookup.py"]
  query = {
    key = "infra-monitoring-secrets"
  }
}

# provider "uptimerobot" {
#   api_key = "...."
# }

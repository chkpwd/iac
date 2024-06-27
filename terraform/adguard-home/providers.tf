terraform {
  required_providers {
    adguard = {
      source  = "gmichels/adguard"
      version = "1.3.0"
    }
  }
}

data "external" "bws_lookup" {
  program = ["python3", "../bws_lookup.py"]
  query = {
    key = "infra-adguard-home"
  }
}

# configuration for adguard home
provider "adguard" {
  host     = "172.16.16.1:8080"
  username = "admin"
  password = data.external.bws_lookup.result["infra-adguard-home_password"]
  scheme   = "http" # defaults to https
  timeout  = 5
}

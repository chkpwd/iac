terraform {
  required_providers {
    adguard = {
      source = "gmichels/adguard"
      version = "1.1.5"
    }
    sops = { 
      source = "carlpett/sops"
      version = "1.0.0"
    }
  }
}

data "http" "bws_lookup" {
  url = "http://mgmt-srv-01:5000/key/infra-adguard-home-secrets"

  request_headers = {
    Accept = "application/json"
    Authorization = "Bearer ${var.BWS_ACCESS_TOKEN}"
  }
}

# configuration for adguard home
provider "adguard" {
  host     = "172.16.16.1:8080"
  username = "admin"
  password = jsondecode(data.http.bws_lookup.response_body).value.password
  scheme   = "http" # defaults to https
  timeout  = 5
}

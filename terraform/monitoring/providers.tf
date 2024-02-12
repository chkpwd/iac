terraform {
  required_providers {
    grafana = {
        source = "grafana/grafana"
        version = ">= 1.28.2"
    }
    sops = { 
      source = "carlpett/sops"
      version = "1.0.0"
    }
  }
}

data "sops_file" "grafana-secrets" {
  source_file = "../terraform.sops.yaml"
}

provider "grafana" {
  url  = "https://grafana.k8s.chkpwd.com"
  auth = data.sops_file.grafana-secrets.data["grafana_api_key"]
}

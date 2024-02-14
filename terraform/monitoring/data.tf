resource "grafana_data_source" "rpi-prometheus" {
  type                = "prometheus"
  name                = "mgmt-srv-01-prometheus"
  uid                 = "mgmt-srv-01-prometheus"
  url                 = "https://rpi-prometheus.k8s.chkpwd.com"
  is_default          = true
  basic_auth_enabled  = true
  basic_auth_username = "chkpwd"

  json_data_encoded = jsonencode({
    prometheusType    = "Prometheus"
    prometheusVersion = "2.49.0" # Some semi-arbitrary, server-side version option
    manageAlerts      = true
    cacheLevel        = "Low"
    httpMethod        = "POST"
    timeInterval      = "15s" # Prom's scrape interval
  })

  secure_json_data_encoded = jsonencode({
    basicAuthPassword = data.sops_file.grafana-secrets.data["rpi_prometheus_password"]
  })
}

resource "grafana_data_source" "k8s-prometheus" {
  type                = "prometheus"
  name                = "kairos-k3s-prometheus"
  uid                 = "kairos-k3s-prometheus"
  url                 = "https://k8s-prometheus.k8s.chkpwd.com"

  json_data_encoded = jsonencode({
    prometheusType    = "Prometheus"
    prometheusVersion = "2.49.0" # Some semi-arbitrary, server-side version option
    manageAlerts      = true
    cacheLevel        = "Low"
    httpMethod        = "POST"
    timeInterval      = "15s" # Prom's scrape interval
  })
}

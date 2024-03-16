data "external" "bws_lookup" {
  program = ["python3","../bws_lookup.py"]
  query = {
    key = "cloud-aws-secrets,infra-network-secrets"
  }
}

data "sops_file" "aws-secrets" {
  source_file = "../terraform.sops.yaml"
}

data "sops_file" "oci-secrets" {
  source_file = "../terraform.sops.yaml"
}

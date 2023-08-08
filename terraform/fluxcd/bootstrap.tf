#===============================================================================
# Fluxcd Resources
#===============================================================================

locals {
  github_repo_url = local.github_repository
}

resource "tls_private_key" "flux_secret" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
}

resource "github_repository_deploy_key" "github_secret" {
  depends_on = [tls_private_key.flux_secret]

  title      = "TF-Flux"
  repository = local.github_repo_url
  key        = tls_private_key.flux_secret.public_key_openssh
  read_only  = "false"
}

resource "flux_bootstrap_git" "kubernetes-cluster" {
  depends_on = [github_repository_deploy_key.github_secret]

  path = "./kubernetes/infrastructure"
  namespace = "chkpwd-ops"
  components_extra = [ "image-reflector-controller", "image-automation-controller" ]
  version = "v2.0.0-rc.3"
}
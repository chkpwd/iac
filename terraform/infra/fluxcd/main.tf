#===============================================================================
# Fluxcd Resources
#===============================================================================

locals {
  github_org        = "chkpwd"
  github_repository = "boilerplates"
}

resource "flux_bootstrap_git" "kubernetes-cluster" {
  path = "kubernetes/infrastructure"
}
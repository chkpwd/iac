terraform {
  backend "remote" {
    hostname     = "app.terraform.io"
    organization = "chkpwd"

    workspaces {
      name = "fluxcd"
    }

  }
}
data "tfe_outputs" "oci" {
  organization = "chkpwd"
  workspace    = "oci"
}

data "tfe_outputs" "aws" {
  organization = "chkpwd"
  workspace    = "aws"
}

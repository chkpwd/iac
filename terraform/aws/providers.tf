#===============================================================================
# AWS Provider
#===============================================================================

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    sops = {
      source  = "carlpett/sops"
      version = "1.0.0"
    }
  }
}

data "sops_file" "aws-secrets" {
  source_file = "../terraform.sops.yaml"
}

# Configure the AWS Provider
provider "aws" {
  region = "us-east-1"
  access_key = "${data.sops_file.aws-secrets.data["aws_access_key_id"]}"
  secret_key = "${data.sops_file.aws-secrets.data["aws_secret_access_key"]}"
}

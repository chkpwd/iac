#===============================================================================
# AWS Provider
#===============================================================================

terraform {
  required_version = "~> 1.12"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    external = {
      source  = "hashicorp/external"
      version = "~> 2"
    }
  }
}

data "external" "bws_lookup" {
  program = ["python3", "../bws_lookup.py"]
  query = {
    key = "cloud-aws-secrets,infra-network-secrets"
  }
}

# Configure the AWS Provider
provider "aws" {
  region     = "us-east-1"
  access_key = data.external.bws_lookup.result["cloud-aws-secrets_aws_access_key_id"]
  secret_key = data.external.bws_lookup.result["cloud-aws-secrets_aws_secret_access_key"]
}

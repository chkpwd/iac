terraform {
  required_version = "~> 1.12"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
    ansible = {
      source  = "ansible/ansible"
      version = "~> 1.4"
    }
    external = {
      source  = "hashicorp/external"
      version = "~> 2"
    }
  }
}

locals {
  bws_keys = [
    "cloud-aws-secrets",
    "infra-network-secrets",
  ]
}

data "external" "bws_lookup" {
  program = ["python3", "../bws_lookup.py"]
  query = {
    keys = jsonencode(local.bws_keys)
  }
}

provider "aws" {
  region     = "us-east-1"
  access_key = data.external.bws_lookup.result["cloud-aws-secrets_aws_access_key_id"]
  secret_key = data.external.bws_lookup.result["cloud-aws-secrets_aws_secret_access_key"]
}

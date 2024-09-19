terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"        
    }
    pgp = {
      source = "ekristen/pgp"
      version = "0.2.4"
    }
}
}

provider "pgp" {
  # Configuration options
}

module "sandbox" {
  source             				      = "./aws_sandbox"
  sandbox_owner_name              = "owner"
  sandbox_owner_arn              = "owner_arn"
  sandbox_user_name               = "user_name"
  inbound_vpn_cidr				        = ["10.0.0.0/24"]
  vpc_cidr                        = "10.0.0.0/16"
}

provider "aws" {
  region = "us-west-2"
  access_key = "owner key id"
  secret_key = "owner secret key"
}

output "sandbox_output" {
    value = module.sandbox.credentials
}

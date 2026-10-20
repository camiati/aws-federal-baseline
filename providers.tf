# Which Terraform and AWS provider versions this code works with,
# and which AWS Region it targets.
#
# Pinning versions keeps every run predictable: the same code
# produces the same result no matter when it runs.

terraform {
  required_version = ">= 1.6"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0" # any 6.x release, but not 7.0
    }
  }
}

provider "aws" {
  region = var.region
}

variable "region" {
  description = "AWS Region to deploy into."
  type        = string
  default     = "us-east-1"
}

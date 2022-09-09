terraform {
  required_version = ">= 1.0.0"
  required_providers {
    aws = {
      source = "hashicorp/aws"
      version = "~> 4.1"
    }
    tfe = {
      source = "hashicorp/tfe"
      version = "~> 0.33"
    }
    
  }
}

data "aws_region" "current" {}
locals {
  region = data.aws_region.current.name
}
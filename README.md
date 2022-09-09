# Terraform Cloud Autoscaling Agent Pool (EC2)

A Terraform module to deploy Terraform Cloud self-hosted agents
that will run on EC2, and scale dynamically in response
to various run notification events on the attached workspace
on Terraform Cloud.

## Setup

* Set the `TFE_TOKEN` environment variable. It'll need to be a highly permissive token (i.e., on the `owners` team) as it needs to be able to create a new agent pool at an organizational level.
* Set the relevant variables to configure your AWS provider.

## Usage

```hcl
locals = {
  tfc_org_name = "acme-org"
  agents_name   = "acme-agents"
}

module "agents" {
  source            = "glenngillen/ec2-agent-pool/module"
  version           = "1.0.0"

  org_name          = local.tfc_org_name
  name              = local.agents_name
  image_id          = "ami-ADA24ADZHAFS"
}

module "agent-scaler" {
  source            = "glenngillen/ec2-agent-pool-autoscaler/module"
  version           = "1.0.0"

  org_name          = local.tfc_org_name
  name              = local.agents_name
  workspace_name    = "my-terraform-cloud-workspace-here"

  asg_name          = module.agents.asg_name
}
```
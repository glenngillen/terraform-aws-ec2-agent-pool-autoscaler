variable "org_name" {
  description = "Organization to create agent pool in."
}

variable "name" {
  description = "Name for the agent pool & resources."
}

variable "workspace_name" {
  description = "Name of the workspace to attach to this agent pool"
}

variable "asg_name" {
  description = "Auto-scaling Group to adjust"
}
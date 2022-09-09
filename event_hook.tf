data "tfe_workspace" "this" {
  name         = var.workspace_name
  organization = var.org_name
}

resource "tfe_notification_configuration" "this" {
  depends_on = [
    aws_lambda_function.webhook,
    aws_api_gateway_deployment.webhook
  ]

  name             = "${var.name}-scaler"
  enabled          = true
  destination_type = "generic"
  triggers         = ["run:created", "run:planning", "run:applying", "run:errored", "run:completed"]
  token 	         = aws_ssm_parameter.notification_token.value
  url              = aws_api_gateway_deployment.webhook.invoke_url
  workspace_id     = data.tfe_workspace.this.id
}
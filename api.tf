data "archive_file" "lambda_zip_inline" {
  type        = "zip"
  output_path = "${path.module}/lambda_zip_inline.zip"
  source {
    content  = <<EOF
import boto3
import hashlib
import hmac
import json
import os

ASG_NAME = os.getenv("ASG_NAME", None)
REGION = os.getenv("REGION", None)
SALT_PATH = os.getenv("SALT_PATH", None)
SSM_PARAM_NAME = os.getenv("SSM_PARAM_NAME", None)

ADD_SERVICE_STATES = {'pending'}
SUB_SERVICE_STATES = {
    'errored',
    'canceled',
    'discarded',
    'planned_and_finished',
    'applied',
    'completed'
}


# Initialize boto3 client at global scope for connection reuse
session = boto3.Session(region_name=REGION)
ssm = session.client('ssm')
asg = session.client('autoscaling')


def lambda_handler(event, context):
    message = bytes(event.get('body'), 'utf-8')
    secret = bytes(ssm.get_parameter(Name=SALT_PATH, WithDecryption=True)['Parameter']['Value'], 'utf-8')
    hash = hmac.new(secret, message, hashlib.sha512)
    signature = event['headers'].get('X-Tfe-Notification-Signature')
    if signature and hash.hexdigest() == signature:
        # HMAC verified
        if event['httpMethod'] == "POST":
            return post(event)
        return get()
    return 'Invalid HMAC'


def get():
    return {
        "statusCode": 200,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*"
        },
        "body": "Ok"
        }


def post(event):
    payload = json.loads(event['body'])
    post_response = "Ok"

    response = asg.describe_auto_scaling_groups(
        AutoScalingGroupNames=[
          ASG_NAME
        ]
    )

    instance_count = response['AutoScalingGroups'][0]['DesiredCapacity']
    print("Current instance count:", int(instance_count))

    if payload and 'run_status' in payload['notifications'][0]:
        body = payload['notifications'][0]
        if body['run_status'] in ADD_SERVICE_STATES:
            post_response = update_instance_count(asg, 'add')
            print("Run status indicates add an agent.")
        elif body['run_status'] in SUB_SERVICE_STATES:
            post_response = update_instance_count(asg, 'sub')
            print("Run status indicates subtract an agent.")

    return {
        "statusCode": 200,
        "body": json.dumps(post_response)
    }


def update_instance_count(client, operation):
    num_runs_queued = int(ssm.get_parameter(Name=SSM_PARAM_NAME)['Parameter']['Value'])
    if operation is 'add':
        num_runs_queued = num_runs_queued + 1
    elif operation is 'sub':
        num_runs_queued=num_runs_queued - 1 if num_runs_queued > 0 else 0
    else:
        return
    response = ssm.put_parameter(Name=SSM_PARAM_NAME, Value=str(num_runs_queued), Type='String', Overwrite=True)

    desired_count = num_runs_queued
    client.set_desired_capacity(
      AutoScalingGroupName=ASG_NAME,
      DesiredCapacity=desired_count,
      HonorCooldown=False
    )

    print("Updated instance count:", desired_count)
    return("Updated instance count:", desired_count)
EOF
    filename = "main.py"
  }
}

resource "aws_lambda_function" "webhook" {
  function_name           = "${var.name}-webhook"
  description             = "Receives webhook notifications from TFC and automatically adjusts the number of tfc agents running."
  code_signing_config_arn = aws_lambda_code_signing_config.this.arn
  role                    = aws_iam_role.lambda_exec.arn
  handler                 = "main.lambda_handler"
  runtime                 = "python3.7"

  filename         = data.archive_file.lambda_zip_inline.output_path
  source_code_hash = data.archive_file.lambda_zip_inline.output_base64sha256

  environment {
    variables = {
      REGION         = local.region
      SALT_PATH      = aws_ssm_parameter.notification_token.name
      ASG_NAME        = var.asg_name
      SSM_PARAM_NAME = aws_ssm_parameter.current_count.name
    }
  }
}

resource "aws_ssm_parameter" "current_count" {
  name        = "${var.name}-tfc-agent-current-count"
  description = "Terraform Cloud agent current count"
  type        = "String"
  value       = 0
}

resource "random_password" "notification_token" {
  length           = 32
  special          = true
}

resource "aws_ssm_parameter" "notification_token" {
  name        = "${var.name}-tfc-notification-token"
  description = "Terraform Cloud webhook notification token"
  type        = "SecureString"
  value       = random_password.notification_token.result
}

resource "aws_iam_role" "lambda_exec" {
  name = "${var.name}-webhook-lambda"
  assume_role_policy = data.aws_iam_policy_document.webhook_assume_role_policy_definition.json
}

data "aws_iam_policy_document" "webhook_assume_role_policy_definition" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      identifiers = ["lambda.amazonaws.com"]
      type        = "Service"
    }
  }
}

resource "aws_iam_role_policy" "lambda_policy" {
  role   = aws_iam_role.lambda_exec.name
  name   = "${var.name}-lambda-webhook-policy"
  policy = data.aws_iam_policy_document.lambda_policy_definition.json
}

data "aws_autoscaling_group" "this" {
  name = var.asg_name
}

data "aws_iam_policy_document" "lambda_policy_definition" {
  statement {
    effect    = "Allow"
    actions   = ["ssm:GetParameter"]
    resources = [aws_ssm_parameter.notification_token.arn, aws_ssm_parameter.current_count.arn]
  }
  statement {
    effect    = "Allow"
    actions   = ["ssm:PutParameter"]
    resources = [aws_ssm_parameter.current_count.arn]
  }
  statement {
    effect    = "Allow"
    actions   = ["autoscaling:SetDesiredCapacity"]
    resources = [data.aws_autoscaling_group.this.arn]
  }
  statement {
    effect    = "Allow"
    actions   = ["autoscaling:Describe*"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy_attachment" "cloudwatch_lambda_attachment" {
  role       = aws_iam_role.lambda_exec.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchLogsFullAccess"
}

resource "aws_lambda_permission" "apigw" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.webhook.function_name
  principal     = "apigateway.amazonaws.com"

  # The "/*/*" portion grants access from any method on any resource
  # within the API Gateway REST API.
  source_arn = "${aws_api_gateway_rest_api.webhook.execution_arn}/*/*"
}

# api gateway
resource "aws_api_gateway_rest_api" "webhook" {
  name        = "${var.name}-webhook"
  description = "TFC webhook receiver for autoscaling tfc-agent"
}

resource "aws_api_gateway_resource" "proxy" {
  rest_api_id = aws_api_gateway_rest_api.webhook.id
  parent_id   = aws_api_gateway_rest_api.webhook.root_resource_id
  path_part   = "{proxy+}"
}

resource "aws_api_gateway_method" "proxy" {
  rest_api_id   = aws_api_gateway_rest_api.webhook.id
  resource_id   = aws_api_gateway_resource.proxy.id
  http_method   = "ANY"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "lambda" {
  rest_api_id = aws_api_gateway_rest_api.webhook.id
  resource_id = aws_api_gateway_method.proxy.resource_id
  http_method = aws_api_gateway_method.proxy.http_method

  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.webhook.invoke_arn
}

resource "aws_api_gateway_method" "proxy_root" {
  rest_api_id   = aws_api_gateway_rest_api.webhook.id
  resource_id   = aws_api_gateway_rest_api.webhook.root_resource_id
  http_method   = "ANY"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "lambda_root" {
  rest_api_id = aws_api_gateway_rest_api.webhook.id
  resource_id = aws_api_gateway_method.proxy_root.resource_id
  http_method = aws_api_gateway_method.proxy_root.http_method

  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.webhook.invoke_arn
}

resource "aws_api_gateway_deployment" "webhook" {
  depends_on = [
    aws_api_gateway_integration.lambda,
    aws_api_gateway_integration.lambda_root,
  ]

  rest_api_id = aws_api_gateway_rest_api.webhook.id
  stage_name  = "test"

  stage_description = "Deployment of ${data.archive_file.lambda_zip_inline.output_base64sha256}"
}

resource "aws_signer_signing_profile" "this" {
  platform_id = "AWSLambda-SHA384-ECDSA"
}

resource "aws_lambda_code_signing_config" "this" {
  allowed_publishers {
    signing_profile_version_arns = [
      aws_signer_signing_profile.this.arn,
    ]
  }

  policies {
    untrusted_artifact_on_deployment = "Warn"
  }
}
"""Sends an email using AWS SES from a Lambda function."""

import boto3


def lambda_handler(event, context):
    ses_client = boto3.client("ses")
    subject = "Test subject from lambda"
    body = "Test body from lambda"
    message = {"Subject": {"Data": subject}, "Body": {"Html": {"Data": body}}}
    response = ses_client.send_email(Source = "from@email.com", Destination = {"ToAddresses": ["to@email.com"]}, Message = message)
    return response

#!/bin/bash

# This will decode the authorization message from the AWS STS AssumeRole API call.
aws sts decode-authorization-message --encoded-message $msg --query DecodedMessage --output text | jq '.'
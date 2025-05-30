#!/bin/bash
# Retrieve security group rules for a specific security group in AWS and save them to CSV files.

echo "cidr_ipv4,description,from_port,protocol,to_port" > ingress_rules.csv
aws ec2 describe-security-group-rules --filters "Name=group-id,Values=<sg_id>" --profile <aws_profile> --region <aws_region> | jq -r '.SecurityGroupRules[] | select(.IsEgress == false) | [.CidrIpv4, .Description, .FromPort, .IpProtocol, .ToPort] | @csv' >> ingress_rules.csv

echo "cidr_ipv4,description,from_port,protocol,to_port" > egress_rules.csv
aws ec2 describe-security-group-rules --filters "Name=group-id,Values=<sg_id>" --profile <aws_profile> --region <aws_region> | jq -r '.SecurityGroupRules[] | select(.IsEgress == true) | [.CidrIpv4, .Description, .FromPort, .IpProtocol, .ToPort] | @csv' >> egress_rules.csv
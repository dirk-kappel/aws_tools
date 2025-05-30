aws s3api create-bucket --bucket <new_bucket_name> --create-bucket-configuration LocationConstraint=us-west-2 --region <aws_region>

aws s3api put-bucket-tagging --bucket <new_bucket_name> --tagging 'TagSet=[{Key=Environment,Value=Production}]'
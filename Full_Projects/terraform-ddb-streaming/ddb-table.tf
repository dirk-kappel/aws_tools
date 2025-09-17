# DynamoDB table for storing message posts
resource "aws_dynamodb_table" "messages" {
  name         = "messages"
  billing_mode = "PAY_PER_REQUEST" # On-demand billing for learning/testing
  hash_key     = "message_id"

  # Enable DynamoDB Streams to capture data modification events
  stream_enabled   = true
  stream_view_type = "NEW_AND_OLD_IMAGES" # Capture full item data before and after changes

  # Primary key attribute
  attribute {
    name = "message_id"
    type = "S" # String
  }

  # Global Secondary Index for querying by timestamp
  # Useful for retrieving messages in chronological order
  attribute {
    name = "timestamp"
    type = "S" # String (ISO 8601 format)
  }

  # Global Secondary Index for querying by author
  # Useful for retrieving all messages from a specific user
  attribute {
    name = "author"
    type = "S" # String
  }

  global_secondary_index {
    name            = "timestamp-index"
    hash_key        = "timestamp"
    projection_type = "ALL" # Include all attributes in the index
  }

  global_secondary_index {
    name            = "author-index"
    hash_key        = "author"
    range_key       = "timestamp" # Sort messages by timestamp within each author
    projection_type = "ALL"       # Include all attributes in the index
  }

  # Optional: Tags for organization
  tags = {
    Name        = "MessagePostsTable"
    Environment = var.environment
    Project     = var.project_name
  }
}
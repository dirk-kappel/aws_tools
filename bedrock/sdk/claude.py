import json
import sys
import time

import boto3
from botocore.exceptions import ClientError

# Claude 3 Haiku pricing (per 1,000 tokens)
CLAUDE_3_HAIKU_PRICING = {
    "input_tokens": 0.00025,  # $0.00025 per 1K input tokens
    "output_tokens": 0.00125,  # $0.00125 per 1K output tokens
}

def calculate_cost(input_tokens, output_tokens, pricing=CLAUDE_3_HAIKU_PRICING):
    """
    Calculate the cost based on token usage and pricing.

    Args:
        input_tokens (int): Number of input tokens
        output_tokens (int): Number of output tokens
        pricing (dict): Pricing per 1,000 tokens

    Returns:
        dict: Cost breakdown

    """
    input_cost = (input_tokens / 1000) * pricing["input_tokens"]
    output_cost = (output_tokens / 1000) * pricing["output_tokens"]
    total_cost = input_cost + output_cost

    return {
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "total_tokens": input_tokens + output_tokens,
        "input_cost": input_cost,
        "output_cost": output_cost,
        "total_cost": total_cost,
        "pricing_used": pricing,
    }

def format_cost_summary(cost_info, execution_time):
    """
    Format a readable cost and performance summary.

    Args:
        cost_info (dict): Cost information from calculate_cost()
        execution_time (float): Execution time in seconds

    Returns:
        str: Formatted summary

    """
    summary = f"""
{'='*50}
BEDROCK EXECUTION SUMMARY
{'='*50}
Model: Claude 3 Haiku
Execution Time: {execution_time:.2f} seconds

Token Usage:
  • Input tokens:  {cost_info['input_tokens']:,}
  • Output tokens: {cost_info['output_tokens']:,}
  • Total tokens:  {cost_info['total_tokens']:,}

Cost Breakdown:
  • Input cost:  ${cost_info['input_cost']:.6f}
  • Output cost: ${cost_info['output_cost']:.6f}
  • Total cost:  ${cost_info['total_cost']:.6f}

Pricing rates (per 1K tokens):
  • Input:  ${cost_info['pricing_used']['input_tokens']:.5f}
  • Output: ${cost_info['pricing_used']['output_tokens']:.5f}
{'='*50}
"""
    return summary

# Main script
prompt_data = "Generate a movie script about a world where humans randomly age to old and young."

client = boto3.client("bedrock-runtime")
model_id = "anthropic.claude-3-haiku-20240307-v1:0"

native_request = {
    "anthropic_version": "bedrock-2023-05-31",
    "max_tokens": 512,
    "temperature": 0.5,
    "messages": [
        {
            "role": "user",
            "content": [{"type": "text", "text": prompt_data}],
        },
    ],
}

request = json.dumps(native_request)

# Start timing
start_time = time.time()

try:
    # Invoke the model with the request
    response = client.invoke_model(modelId=model_id, body=request)

    # Stop timing
    end_time = time.time()
    execution_time = end_time - start_time

except (ClientError, Exception) as e:
    print(f"ERROR: Can't invoke '{model_id}'. Reason: {e}")
    sys.exit(1)

# Decode the response body
model_response = json.loads(response["body"].read())

# Extract response text
response_text = model_response["content"][0]["text"]

# Extract usage information (token counts)
usage = model_response.get("usage", {})
input_tokens = usage.get("input_tokens", 0)
output_tokens = usage.get("output_tokens", 0)

# Calculate costs
cost_info = calculate_cost(input_tokens, output_tokens)

# Print the response
print("GENERATED CONTENT:")
print("-" * 30)
print(response_text)
print("-" * 30)

# Print cost summary
print(format_cost_summary(cost_info, execution_time))

# Optional: Save cost information to a file for tracking
cost_log = {
    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
    "model": model_id,
    "execution_time": execution_time,
    "prompt_length": len(prompt_data),
    "response_length": len(response_text),
    **cost_info,
}

# Uncomment the following lines to save cost data to a JSON file
# import os
# log_file = "bedrock_cost_log.json"
#
# if os.path.exists(log_file):
#     with open(log_file, 'r') as f:
#         logs = json.load(f)
# else:
#     logs = []
#
# logs.append(cost_log)
#
# with open(log_file, 'w') as f:
#     json.dump(logs, f, indent=2)
#
# print(f"Cost information saved to {log_file}")

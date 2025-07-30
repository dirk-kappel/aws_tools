# Use the native inference API to create an image with Amazon Titan Image Generator

import base64
import json
import random
import time
from pathlib import Path

import boto3

# Amazon Titan Image Generator pricing
# Note: Premium quality is automatically used for HD resolutions (1024x1024 and above)
TITAN_IMAGE_PRICING = {
    "standard_quality": 0.04,  # $0.04 per image (<=50 steps, lower resolutions)
    "premium_quality": 0.08,   # $0.08 per image (>50 steps or HD resolutions)
}

def calculate_image_cost(num_images, quality="standard", steps=None):
    """
    Calculate the cost for image generation.

    Args:
        num_images (int): Number of images generated
        quality (str): "standard" or "premium"
        steps (int): Number of steps (if provided, overrides quality)

    Returns:
        dict: Cost breakdown

    """
    # Determine quality based on steps if provided
    if steps is not None:
        actual_quality = "premium" if steps > 50 else "standard"
    else:
        actual_quality = quality.lower()

    cost_per_image = TITAN_IMAGE_PRICING.get(f"{actual_quality}_quality", TITAN_IMAGE_PRICING["standard_quality"])
    total_cost = num_images * cost_per_image

    return {
        "num_images": num_images,
        "quality": actual_quality,
        "steps": steps,
        "cost_per_image": cost_per_image,
        "total_cost": total_cost,
        "pricing_used": TITAN_IMAGE_PRICING
    }

def format_image_cost_summary(cost_info, execution_time, image_config):
    """
    Format a readable cost and performance summary.

    Args:
        cost_info (dict): Cost information from calculate_image_cost()
        execution_time (float): Execution time in seconds
        image_config (dict): Image generation configuration

    Returns:
        str: Formatted summary

    """
    summary = f"""
{'='*50}
BEDROCK HD IMAGE GENERATION SUMMARY
{'='*50}
Model: Amazon Titan Image Generator v1
Execution Time: {execution_time:.2f} seconds

Image Configuration:
  • Number of images: {cost_info['num_images']}
  • Quality: {cost_info['quality'].title()}
  • Resolution: {image_config.get('width', 'N/A')}x{image_config.get('height', 'N/A')} (HD)
  • CFG Scale: {image_config.get('cfgScale', 'N/A')}
  • Seed: {image_config.get('seed', 'N/A')}

Cost Breakdown:
  • Cost per image: ${cost_info['cost_per_image']:.4f}
  • Total cost: ${cost_info['total_cost']:.4f}

Pricing rates:
  • Standard quality: ${cost_info['pricing_used']['standard_quality']:.4f} per image
  • Premium quality: ${cost_info['pricing_used']['premium_quality']:.4f} per image
{'='*50}
"""
    return summary

# Create a Bedrock Runtime client in the AWS Region of your choice.
client = boto3.client("bedrock-runtime", region_name="us-east-1")

# Set the model ID, e.g., Titan Image Generator G1.
model_id = "amazon.titan-image-generator-v1"

# Define the image generation prompt for the model.
prompt = "An image of a telemark skier in action. He is skiing down a steep mountain rock chute in Colorado. The sun is shining and there is a blue sky. Ensure the facial features of the skier are visible, and the image is in high definition. It is a female skier and she has long blonde hair"

# Generate a random seed.
seed = random.randint(0, 2147483647)

# Format the request payload using the model's native structure.
# Using HD resolution (1024x1024) for high-definition output
native_request = {
    "taskType": "TEXT_IMAGE",
    "textToImageParams": {"text": prompt},
    "imageGenerationConfig": {
        "numberOfImages": 1,
        "quality": "premium",  # Use premium quality for HD
        "cfgScale": 8.0,
        "height": 1024,  # HD resolution
        "width": 1024,   # HD resolution
        "seed": seed,
    },
}

# Convert the native request to JSON.
request = json.dumps(native_request)

# Start timing
start_time = time.time()

# Invoke the model with the request.
response = client.invoke_model(modelId=model_id, body=request)

# Stop timing
end_time = time.time()
execution_time = end_time - start_time

# Decode the response body.
model_response = json.loads(response["body"].read())

# Extract the image data.
base64_image_data = model_response["images"][0]

# Save the generated image to a local folder using pathlib.
output_dir = Path("output")
output_dir.mkdir(exist_ok=True)

# Find the next available filename
i = 1
while (output_dir / f"titan_hd_{i}.png").exists():
    i += 1

image_data = base64.b64decode(base64_image_data)

image_path = output_dir / f"titan_hd_{i}.png"
image_path.write_bytes(image_data)

print(f"The generated HD image has been saved to {image_path}")

# Calculate costs
num_images = native_request["imageGenerationConfig"]["numberOfImages"]
quality = native_request["imageGenerationConfig"]["quality"]
cost_info = calculate_image_cost(num_images, quality)

# Print cost summary
print(format_image_cost_summary(cost_info, execution_time, native_request["imageGenerationConfig"]))

# Optional: Save cost information to a file for tracking
cost_log = {
    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
    "model": model_id,
    "execution_time": execution_time,
    "prompt": prompt,
    "image_config": native_request["imageGenerationConfig"],
    "image_path": str(image_path),  # Convert Path to string for JSON serialization
    **cost_info
}

# Uncomment the following lines to save cost data to a JSON file
# log_file = Path("bedrock_image_cost_log.json")
#
# if log_file.exists():
#     with log_file.open('r') as f:
#         logs = json.load(f)
# else:
#     logs = []
#
# logs.append(cost_log)
#
# with log_file.open('w') as f:
#     json.dump(logs, f, indent=2)
#
# print(f"Cost information saved to {log_file}")

# Additional utility functions for batch cost tracking
def estimate_batch_cost(num_images, quality="standard"):
    """Estimate cost for generating multiple images."""
    cost_info = calculate_image_cost(num_images, quality)
    print(f"Estimated cost for {num_images} {quality} quality images: ${cost_info['total_cost']:.4f}")
    return cost_info

# Example usage:
# estimate_batch_cost(10, "standard")  # Estimate cost for 10 standard quality images

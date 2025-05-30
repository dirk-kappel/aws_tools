#!/usr/bin/env python3
"""
HTTP JSON Data Fetcher.

A simple utility for making GET requests to APIs that return JSON data.
Includes comprehensive error handling for common HTTP issues including
connection errors, timeouts, HTTP status errors, and JSON parsing errors.

Features:
- 10-second request timeout
- Detailed exception handling with informative error messages
- JSON response validation
- Pretty-printed JSON output with proper indentation

Example usage:
    python get_url.py

The script will fetch user data from JSONPlaceholder test API and display
it in a formatted JSON structure, or show appropriate error messages if
the request fails.
"""

import json

import requests

# --------------- Variables ---------------
url = "https://jsonplaceholder.typicode.com/users/1"

def get_user_data(url):
    """
    Fetches user data from the specified URL.

    Args:
        url (str): The URL to send the GET request to.

    Returns:
        dict: The JSON response from the server, or None if an error occurs.

    """
    try:
        # Send GET request
        response = requests.get(url, timeout=10)
        # Check if the request was successful
        response.raise_for_status()
        # Parse JSON response
        data = response.json()
    except requests.exceptions.HTTPError as errh:
        print(f"HTTP Error: {errh}")
    except requests.exceptions.ConnectionError as errc:
        print(f"Error Connecting: {errc}")
    except requests.exceptions.Timeout as errt:
        print(f"Timeout Error: {errt}")
    except requests.exceptions.JSONDecodeError as errj:
        print(f"JSON Decode Error: {errj}")
        print("Response content:")
        print(response.text[:500])  # Print first 500 characters
    except requests.exceptions.RequestException as err:
        print(f"Error: {err}")
    else:
        return data


if __name__ == "__main__":
    user_data = get_user_data(url)
    if user_data:
        print("Success! Received data:")
        print(json.dumps(user_data, indent=2, ensure_ascii=False))
    else:
        print("Failed to retrieve valid JSON data")

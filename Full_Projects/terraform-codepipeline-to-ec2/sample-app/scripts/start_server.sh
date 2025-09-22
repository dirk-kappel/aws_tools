#!/bin/bash
# Start Server Script for CodeDeploy

echo "Starting Apache HTTP Server..."

# Start Apache service
systemctl start httpd

# Check if Apache started successfully
if systemctl is-active --quiet httpd; then
    echo "Apache HTTP Server started successfully"
    echo "Web application is now accessible"
else
    echo "Failed to start Apache HTTP Server"
    exit 1
fi

# Display server status
systemctl status httpd --no-pager
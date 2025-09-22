#!/bin/bash
# Stop Server Script for CodeDeploy

echo "Stopping Apache HTTP Server..."

# Stop Apache service if it's running
if systemctl is-active --quiet httpd; then
    systemctl stop httpd
    echo "Apache HTTP Server stopped successfully"
else
    echo "Apache HTTP Server was not running"
fi

# Verify it stopped
if ! systemctl is-active --quiet httpd; then
    echo "Apache HTTP Server is confirmed stopped"
else
    echo "Warning: Apache HTTP Server may still be running"
fi
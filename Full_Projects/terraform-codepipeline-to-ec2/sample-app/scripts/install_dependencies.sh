#!/bin/bash
# Install Dependencies Script for CodeDeploy

echo "Installing dependencies..."

# Update system packages
yum update -y

# Install Apache web server if not already installed
if ! rpm -qa | grep -qw httpd; then
    echo "Installing Apache HTTP Server..."
    yum install -y httpd
else
    echo "Apache HTTP Server already installed"
fi

# Ensure Apache is enabled to start on boot
systemctl enable httpd

# Set permissions for web directory
chown -R apache:apache /var/www/html
chmod -R 755 /var/www/html

echo "Dependencies installation completed successfully"
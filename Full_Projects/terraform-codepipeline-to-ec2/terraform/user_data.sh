#!/bin/bash
# Amazon Linux 2023 setup script
dnf update -y

# Install CodeDeploy agent (not pre-installed on AL2023)
dnf install -y ruby wget
cd /home/ec2-user
wget https://aws-codedeploy-us-east-1.s3.us-east-1.amazonaws.com/latest/install
chmod +x ./install
./install auto

# Ensure CodeDeploy agent is enabled and started
systemctl enable codedeploy-agent
systemctl start codedeploy-agent

# Install Apache
dnf install -y httpd
systemctl enable httpd
systemctl start httpd

# Create web directory and set proper permissions (don't create index.html - let CodeDeploy handle it)
mkdir -p /var/www/html
chown -R apache:apache /var/www/html
chmod -R 755 /var/www/html
packer {
  required_plugins {
    amazon = {
      version = ">= 1.2.8"
      source  = "github.com/hashicorp/amazon"
    }
  }
}

variable "project_name" {
  type    = string
  default = "codepipeline-learning"
}

variable "region" {
  type    = string
  default = "us-east-1"
}

# Data source to get the latest Amazon Linux 2023 AMI
data "amazon-ami" "amazon_linux" {
  filters = {
    name                = "al2023-ami-*-x86_64"
    root-device-type    = "ebs"
    virtualization-type = "hvm"
  }
  most_recent = true
  owners      = ["amazon"]
  region      = var.region
}

# Build the AMI
build {
  name = "codepipeline-learning-ami"
  sources = [
    "source.amazon-ebs.main"
  ]

  # Install CodeDeploy agent and Apache
  provisioner "shell" {
    inline = [
      "sudo dnf update -y",
      
      # Install CodeDeploy agent
      "sudo dnf install -y ruby wget",
      "cd /home/ec2-user",
      "wget https://aws-codedeploy-us-east-1.s3.us-east-1.amazonaws.com/latest/install",
      "chmod +x ./install",
      "sudo ./install auto",
      "sudo systemctl enable codedeploy-agent",
      
      # Install Apache
      "sudo dnf install -y httpd",
      "sudo systemctl enable httpd",
      
      # Set up web directory permissions
      "sudo mkdir -p /var/www/html",
      "sudo chown -R apache:apache /var/www/html",
      "sudo chmod -R 755 /var/www/html",
      
      # Clean up
      "sudo dnf clean all"
    ]
  }

  # Add build timestamp and version info
  provisioner "shell" {
    inline = [
      "echo 'AMI Build Date: ${timestamp()}' | sudo tee /var/log/ami-build-info.txt",
      "echo 'Built for: ${var.project_name}' | sudo tee -a /var/log/ami-build-info.txt"
    ]
  }
}

# Source configuration
source "amazon-ebs" "main" {
  ami_name      = "${var.project_name}-{{timestamp}}"
  instance_type = "t2.micro"
  region        = var.region
  source_ami    = data.amazon-ami.amazon_linux.id

  ssh_username = "ec2-user"

  tags = {
    Name        = "${var.project_name}-ami"
    Environment = "production"
    BuildDate   = "{{timestamp}}"
    Project     = var.project_name
  }
}
# ─────────────────────────────────────────────────────────────────
# TAKE Server — AWS Nitro Enclave Deployment
# ─────────────────────────────────────────────────────────────────
#
# Provisions an EC2 instance with Nitro Enclave support.
# The TAKE server runs on the host, and the TEE key derivation
# (k1, k2 from master key) runs inside the Nitro Enclave.
#
# Usage:
#   cd infra/
#   terraform init
#   terraform plan
#   terraform apply
#
# After apply:
#   ssh -i <key> ec2-user@<public_ip>
#   The server auto-starts via user-data script.
# ─────────────────────────────────────────────────────────────────

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# ─────────────────────────────────────────────────────────────────
# VPC + Networking
# ─────────────────────────────────────────────────────────────────

resource "aws_vpc" "take_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = { Name = "take-vpc" }
}

resource "aws_internet_gateway" "take_igw" {
  vpc_id = aws_vpc.take_vpc.id
  tags   = { Name = "take-igw" }
}

resource "aws_subnet" "take_public" {
  vpc_id                  = aws_vpc.take_vpc.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "${var.aws_region}a"
  map_public_ip_on_launch = true

  tags = { Name = "take-public-subnet" }
}

resource "aws_route_table" "take_public_rt" {
  vpc_id = aws_vpc.take_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.take_igw.id
  }

  tags = { Name = "take-public-rt" }
}

resource "aws_route_table_association" "take_public_assoc" {
  subnet_id      = aws_subnet.take_public.id
  route_table_id = aws_route_table.take_public_rt.id
}

# ─────────────────────────────────────────────────────────────────
# Security Group
# ─────────────────────────────────────────────────────────────────

resource "aws_security_group" "take_sg" {
  name_prefix = "take-server-"
  description = "TAKE server - SSH + Flask API"
  vpc_id      = aws_vpc.take_vpc.id

  # SSH
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.allowed_cidr]
    description = "SSH access"
  }

  # Flask API
  ingress {
    from_port   = 5000
    to_port     = 5000
    protocol    = "tcp"
    cidr_blocks = [var.allowed_cidr]
    description = "TAKE API"
  }

  # Outbound
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "take-server-sg" }
}

# ─────────────────────────────────────────────────────────────────
# IAM Role (for Nitro Enclave attestation + CloudWatch)
# ─────────────────────────────────────────────────────────────────

resource "aws_iam_role" "take_ec2_role" {
  name = "take-ec2-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "take_ssm" {
  role       = aws_iam_role.take_ec2_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "take_profile" {
  name = "take-ec2-profile"
  role = aws_iam_role.take_ec2_role.name
}

# ─────────────────────────────────────────────────────────────────
# EC2 Instance with Nitro Enclave
# ─────────────────────────────────────────────────────────────────

data "aws_ami" "amazon_linux_2023" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

resource "aws_instance" "take_server" {
  ami                    = data.aws_ami.amazon_linux_2023.id
  instance_type          = var.instance_type
  key_name               = var.key_name
  subnet_id              = aws_subnet.take_public.id
  vpc_security_group_ids = [aws_security_group.take_sg.id]
  iam_instance_profile   = aws_iam_instance_profile.take_profile.name

  # Enable Nitro Enclave
  enclave_options {
    enabled = true
  }

  root_block_device {
    volume_size = 30
    volume_type = "gp3"
  }

  user_data = <<-EOF
    #!/bin/bash
    set -e

    # ── System setup ──
    yum update -y
    yum install -y python3 python3-pip docker git sqlite wget bzip2

    # ── Nitro Enclave CLI ──
    amazon-linux-extras install aws-nitro-enclaves-cli -y 2>/dev/null || \
      yum install -y aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel

    # Start and enable services
    systemctl start docker
    systemctl enable docker
    systemctl start nitro-enclaves-allocator
    systemctl enable nitro-enclaves-allocator

    # Add ec2-user to docker + ne groups
    usermod -aG docker ec2-user
    usermod -aG ne ec2-user

    # Configure enclave memory (1024MB required for Python image)
    cat > /etc/nitro_enclaves/allocator.yaml <<ALLOCATOR
    ---
    memory_mib: 1024
    cpu_count: 2
    ALLOCATOR
    systemctl restart nitro-enclaves-allocator

    chown -R ec2-user:ec2-user /home/ec2-user

    echo "[TAKE] System setup complete. Project deployment handled by Terraform provisioners."
  EOF

  tags = {
    Name    = "take-server"
    Project = "TAKE"
  }

  # Ensure the instance is up and accessible before provisioners run
  provisioner "remote-exec" {
    connection {
      type        = "ssh"
      user        = "ec2-user"
      private_key = file("${path.module}/my-key.pem")
      host        = self.public_ip
    }

    inline = [
      "echo 'Waiting for cloud-init to finish...'",
      "cloud-init status --wait",
      "mkdir -p /home/ec2-user/take-oprf-protocol"
    ]
  }

  # First, automatically create the tarball locally from the fresh source code
  provisioner "local-exec" {
    command = "cd ${path.module}/.. && tar --exclude='infra/.terraform' --exclude='android' --exclude='demo' -czf take-oprf-protocol.tar.gz server infra requirements.txt"
  }

  # Upload the freshly created project archive to the EC2 instance
  provisioner "file" {
    connection {
      type        = "ssh"
      user        = "ec2-user"
      private_key = file("${path.module}/my-key.pem")
      host        = self.public_ip
    }

    source      = "${path.module}/../take-oprf-protocol.tar.gz"
    destination = "/home/ec2-user/take-oprf-protocol.tar.gz"
  }

  # Extract the folder, install dependencies, build enclave, and start service
  provisioner "remote-exec" {
    connection {
      type        = "ssh"
      user        = "ec2-user"
      private_key = file("${path.module}/my-key.pem")
      host        = self.public_ip
    }

    inline = [
      "cd /home/ec2-user",
      "mkdir -p take-oprf-protocol",
      "tar -xzf take-oprf-protocol.tar.gz -C take-oprf-protocol",
      "rm -f take-oprf-protocol.tar.gz",

      "cd /home/ec2-user/take-oprf-protocol",
      "pip3 install -r requirements.txt",

      "TAKE_MASTER_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(32))')",
      "echo \"TAKE_MASTER_KEY=$TAKE_MASTER_KEY\" >> /home/ec2-user/.bashrc",
      "sudo rm -f /home/ec2-user/.take_master_key",
      "echo \"$TAKE_MASTER_KEY\" > /home/ec2-user/.take_master_key",
      "chmod 600 /home/ec2-user/.take_master_key",

      "cd /home/ec2-user/take-oprf-protocol/infra/enclave",
      "sudo docker build -t take-enclave .",
      "sudo nitro-cli build-enclave --docker-uri take-enclave --output-file take-enclave.eif",
      "sudo nitro-cli run-enclave --eif-path take-enclave.eif --memory 1024 --cpu-count 2 --debug-mode",
      "sleep 3",

      "cd /home/ec2-user/take-oprf-protocol",
      "chmod +x server/crypto/models/download_models.sh",
      "./server/crypto/models/download_models.sh",

      "echo '[Unit]' | sudo tee /etc/systemd/system/take-server.service",
      "echo 'Description=TAKE Protocol Flask Server' | sudo tee -a /etc/systemd/system/take-server.service",
      "echo 'After=network.target' | sudo tee -a /etc/systemd/system/take-server.service",
      "echo '[Service]' | sudo tee -a /etc/systemd/system/take-server.service",
      "echo 'User=ec2-user' | sudo tee -a /etc/systemd/system/take-server.service",
      "echo 'WorkingDirectory=/home/ec2-user/take-oprf-protocol' | sudo tee -a /etc/systemd/system/take-server.service",
      "echo 'Environment=TAKE_USE_ENCLAVE=true' | sudo tee -a /etc/systemd/system/take-server.service",
      "echo 'ExecStart=/usr/bin/python3 -m server.app' | sudo tee -a /etc/systemd/system/take-server.service",
      "echo 'Restart=always' | sudo tee -a /etc/systemd/system/take-server.service",
      "echo '[Install]' | sudo tee -a /etc/systemd/system/take-server.service",
      "echo 'WantedBy=multi-user.target' | sudo tee -a /etc/systemd/system/take-server.service",

      "sudo systemctl daemon-reload",
      "sudo systemctl enable take-server",
      "sudo systemctl restart take-server"
    ]
  }
}

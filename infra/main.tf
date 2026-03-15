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
    yum install -y python3 python3-pip docker git sqlite

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

    # Configure enclave memory (512MB for our small enclave)
    cat > /etc/nitro_enclaves/allocator.yaml <<ALLOCATOR
    ---
    memory_mib: 512
    cpu_count: 2
    ALLOCATOR
    systemctl restart nitro-enclaves-allocator

    # ── Deploy TAKE server ──
    cd /home/ec2-user

    # Clone the project from GitHub (replace with your actual repo URL once published)
    git clone https://github.com/karimzakzouk/take-oprf-protocol.git take-project
    
    # Install dependencies

    pip3 install -r take-project/requirements.txt

    # Generate master key
    export TAKE_MASTER_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
    echo "TAKE_MASTER_KEY=$TAKE_MASTER_KEY" >> /home/ec2-user/.bashrc

    # Save master key for enclave sealing (in production: use KMS)
    echo "$TAKE_MASTER_KEY" > /home/ec2-user/.take_master_key
    chmod 600 /home/ec2-user/.take_master_key

    # ── Build Nitro Enclave image ──
    if [ -d take-project/infra/enclave ]; then
      cd take-project/infra/enclave
      docker build -t take-enclave .
      nitro-cli build-enclave --docker-uri take-enclave --output-file take-enclave.eif
      echo "[TAKE] Enclave image built: take-enclave.eif"
    fi

    echo "[TAKE] Server deployment complete."
  EOF

  tags = {
    Name    = "take-server"
    Project = "TAKE"
  }
}

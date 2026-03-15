variable "aws_region" {
  description = "AWS region to deploy in"
  type        = string
  default     = "us-east-1"
}

variable "instance_type" {
  description = "EC2 instance type — must support Nitro Enclaves (e.g. m5.xlarge, c5.xlarge)"
  type        = string
  default     = "m5.xlarge"
}

variable "key_name" {
  description = "Name of an existing EC2 Key Pair for SSH access"
  type        = string
}

variable "allowed_cidr" {
  description = "CIDR block allowed to access the server (SSH + API). Use your IP/32 for security."
  type        = string
  default     = "0.0.0.0/0"
}

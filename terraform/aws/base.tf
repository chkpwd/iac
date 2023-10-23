# Create the VPC
resource "aws_vpc" "main" {
  cidr_block           = var.network_configuration.vpc_cidr
  enable_dns_hostnames = true
  tags = {
    Name = "terrform_vpc"
  }
}

# Define the public subnet
resource "aws_subnet" "main" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.network_configuration.public_subnet_cidr
  availability_zone       = var.availability_zone
  map_public_ip_on_launch = true
  tags = {
    Name = "terrform_public_subnet"
  }
}

# Create Internet Gateway
resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
}

# Define the public route table
resource "aws_route_table" "main" {
  vpc_id = aws_vpc.main.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }
}

# Assign the public route table to the public subnet
resource "aws_route_table_association" "main" {
  subnet_id      = aws_subnet.main.id
  route_table_id = aws_route_table.main.id
}

resource "aws_security_group" "main" {
  name        = "tf-security-group"
  description = "Default security group for Terraform"
  vpc_id      = aws_vpc.main.id 

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0 
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    "Terraform" = "true",
    "Name" = "allow_ssh"
  }
}

resource "aws_key_pair" "main" {
  key_name   = "main_creds"
  public_key = file(var.ssh_configuration.public_key)
}

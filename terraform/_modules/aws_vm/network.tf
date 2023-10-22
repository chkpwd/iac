# Create the VPC
resource "aws_vpc" "main" {
  cidr_block           = var.network_configuration.vpc_cidr
  enable_dns_hostnames = true
}

# Define the public subnet
resource "aws_subnet" "main" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = var.network_configuration.public_subnet_cidr
  availability_zone = var.availability_zone
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

resource "aws_key_pair" "main" {
  key_name   = "main_creds"
  public_key = file(var.ssh_configuration.public_key)
}

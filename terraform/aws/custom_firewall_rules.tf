resource "aws_security_group" "secondary" {
  name        = "app-rules-group"
  description = "Custom security rules for apps"
  vpc_id      = aws_vpc.main.id 

  ingress {
    from_port   = 3000
    to_port     = 3000
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    "Terraform" = "true",
    "Name" = "custom_rules"
  }
}

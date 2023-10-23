resource "aws_instance" "main" {
  ami                    = var.instance_spec.ami
  instance_type          = var.instance_spec.type
  key_name               = var.instance_spec.key_name
  subnet_id              = var.subnet_id
  vpc_security_group_ids = var.vpc_security_groups
  tags = {
    Name = var.instance_spec.name
  }
}

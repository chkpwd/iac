resource "aws_instance" "t3-instance" {
  ami                    = var.instance_spec.ami
  instance_type          = var.instance_spec.type
  key_name               = var.instance_spec.key_name
  vpc_security_group_ids = [aws_security_group.main.id]

  tags = {
    Name = "t3-general"
  }

  connection {
    type        = "ssh"
    user        = var.instance_spec.connection.user
    private_key = file(var.ssh_configuration.private_key)
    host        = aws_instance.t3-instance.public_ip
    timeout     = "2m"
  }
}

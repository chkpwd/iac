locals {
  # amiFilter=[{"Name":"owner-id","Values":["136693071363"]},{"Name":"name","Values":["debian-12-amd64-*"]}]
  # currentImageName=debian-12-amd64-20230711
  ami = "ami-06db4d78cb1d3bbf9"
}

module "ct-01-ec2" {
  source = "../_modules/aws_vm"
  instance_spec = {
    name     = "ct-01-ec2"
    ami      = local.ami
    type     = "t2.micro"
    key_name = aws_key_pair.main.key_name
  }
  subnet_id           = aws_subnet.main.id
  vpc_security_groups = [aws_security_group.main.id, aws_security_group.secondary.id]
}

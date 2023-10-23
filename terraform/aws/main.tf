module "ct-01-ec2" {
  source                         = "../_modules/aws_vm"
  instance_spec                  = {
    name                         = "ct-01-ec2"
    ami                          = "ami-06db4d78cb1d3bbf9" # Debian 12 amd64
    type                         = "t2.micro"
    key_name                     = aws_key_pair.main.key_name
  }
  subnet_id                      = aws_subnet.main.id
  vpc_security_groups            = [ aws_security_group.main.id ]
}

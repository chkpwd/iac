module "ct-01-ec2" {
  source                         = "../_modules/aws_vm"
  instance_spec                  = {
    ami                          = "ami-06db4d78cb1d3bbf9" # Debian 12 amd64
    type                         = "t2.micro"
    key_name                     = "ct-01-ec2"
    connection                   = {
      user        = "chkpwd"
      private_key = file(var.ssh_configuration.private_key)
    }
  }
  ssh_allowed_ips                = []
}

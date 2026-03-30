locals { # https://docs.renovatebot.com/modules/versioning/aws-machine-image/ -- At the moment every AMI that matches the regex ^ami-[a-z0-9]{17}$ is considered a valid "release".
  # amiFilter=[{"Name":"owner-id","Values":["136693071363"]},{"Name":"name","Values":["debian-12-amd64-*"]}]
  # currentImageName=debian-12-amd64-20230711
  ami = "ami-023a5c1706f994759"
}

module "ct-01-ec2" {
  source = "../_modules/aws_vm"
  instance_spec = {
    name     = "ct-01-ec2"
    ami      = local.ami
    type     = "t3.small"
    key_name = aws_key_pair.main.key_name
  }
  subnet_id           = aws_subnet.main.id
  vpc_security_groups = [aws_security_group.main.id, aws_security_group.secondary.id]
}

resource "ansible_host" "ct-01-ec2" {
  name   = module.ct-01-ec2.name
  groups = ["aws", "linux", "docker_hosts", "gatus"]
  variables = {
    ansible_host                 = module.ct-01-ec2.public_ip,
    ansible_user                 = "admin",
    ansible_ssh_private_key_file = "~/.ssh/aws",
    ansible_python_interpreter   = "/usr/bin/python3"
  }
}

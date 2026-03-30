output "name" {
  value       = aws_instance.main.tags.Name
  description = "Name of the EC2 instance"
}

output "public_ip" {
  value       = aws_instance.main.public_ip
  description = "Public IP of the instance"
}

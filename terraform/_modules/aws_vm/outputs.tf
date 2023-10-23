output "public_ip" {
  value       = aws_instance.main.public_ip
  description = "Public IP of the instance"
}

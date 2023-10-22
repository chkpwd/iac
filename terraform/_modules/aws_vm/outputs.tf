output "public_ip" {
  value       = aws_instance.t3-instance.public_ip
  description = "Public IP of the instance"
}

output "ct-01-ec2_public_ip" {
  value = module.ct-01-ec2.public_ip
}

output "renovate_access_key_id" {
  value     = aws_iam_access_key.renovate.id
  sensitive = true
}

output "renovate_secret_access_key" {
  value     = aws_iam_access_key.renovate.secret
  sensitive = true
}

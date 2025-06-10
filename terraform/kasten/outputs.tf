output "aws_access_key_id" {
  value     = aws_iam_access_key.kasten.id
  sensitive = true
}

output "aws_secret_access_key" {
  value     = aws_iam_access_key.kasten.secret
  sensitive = true
}

output "aws_iam_role_arn" {
  value = aws_iam_role.kasten_k10.arn
}

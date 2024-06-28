output "temp_user_password" {
  value     = random_password.temp_password.result
  sensitive = true
}

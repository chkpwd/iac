resource "minio_iam_user" "main" {
  name          = "restic_k8s"
  force_destroy = true
  tags = {
    tag-key = "restic"
  }
}

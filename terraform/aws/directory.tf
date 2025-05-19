resource "aws_iam_policy" "renovate" {
  name        = "renovate"
  path        = "/"
  description = "Allow Renovate access to describe EC2 images"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "AllowEc2ImageLookup"
        Effect   = "Allow"
        Action   = ["ec2:DescribeImages"]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_user" "renovate" {
  name = "renovate"
  path = "/system/"

  tags = {
    Environment = "automation"
    Purpose     = "renovate-ami-lookup"
  }
}

resource "aws_iam_user_policy_attachment" "renovate_attach" {
  user       = aws_iam_user.renovate.name
  policy_arn = aws_iam_policy.renovate.arn
}

resource "aws_iam_access_key" "renovate" {
  user = aws_iam_user.renovate.name
}


variable "env" {
  description = "Deployment environment"
  type        = string
  default     = "staging"
}

variable "region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "zone1" {
  description = "First availability zone"
  type        = string
  default     = "us-east-1a"
}

variable "zone2" {
  description = "Second availability zone"
  type        = string
  default     = "us-east-1b"
}

variable "eks_name" {
  description = "EKS cluster base name"
  type        = string
  default     = "kasten"
}

variable "eks_version" {
  description = "EKS Kubernetes version"
  type        = string
  default     = "1.32"
}

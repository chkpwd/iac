resource "aws_eks_cluster" "eks" {
  name     = "${var.eks_name}-${var.env}"
  version  = var.eks_version
  role_arn = aws_iam_role.eks.arn

  vpc_config {
    endpoint_private_access = false
    endpoint_public_access  = true
    subnet_ids = [
      aws_subnet.private_zone1.id,
      aws_subnet.private_zone2.id
    ]
  }

  access_config {
    authentication_mode                         = "API"
    bootstrap_cluster_creator_admin_permissions = true
  }

  depends_on = [aws_iam_role_policy_attachment.eks]
}

resource "aws_eks_node_group" "general" {
  cluster_name    = aws_eks_cluster.eks.name
  version         = var.eks_version
  node_group_name = "general"
  node_role_arn   = aws_iam_role.nodes.arn

  subnet_ids = [
    aws_subnet.private_zone1.id,
    aws_subnet.private_zone2.id
  ]

  capacity_type  = "ON_DEMAND"
  instance_types = ["t3.large"]

  scaling_config {
    desired_size = 1
    max_size     = 3
    min_size     = 0
  }

  update_config {
    max_unavailable = 1
  }

  labels = {
    role = "general"
  }

  depends_on = [
    aws_iam_role_policy_attachment.amazon_eks_worker_node_policy,
    aws_iam_role_policy_attachment.amazon_eks_cni_policy,
    aws_iam_role_policy_attachment.amazon_ec2_container_registry_read_only,
  ]

  lifecycle {
    ignore_changes = [scaling_config[0].desired_size]
  }
}

resource "aws_eks_addon" "pod_identity" {
  cluster_name  = aws_eks_cluster.eks.name
  addon_name    = "eks-pod-identity-agent"
  addon_version = "v1.3.7-eksbuild.2"
}

resource "aws_eks_pod_identity_association" "ebs_csi_driver" {
  cluster_name    = aws_eks_cluster.eks.name
  namespace       = "kube-system"
  service_account = "ebs-csi-controller-sa"
  role_arn        = aws_iam_role.ebs_csi_driver.arn
}

resource "aws_eks_addon" "ebs_csi_driver" {
  cluster_name  = aws_eks_cluster.eks.name
  addon_name    = "aws-ebs-csi-driver"
  addon_version = "v1.44.0-eksbuild.1"
  depends_on    = [aws_eks_node_group.general]
}

resource "kubernetes_storage_class" "ebs_gp3" {
  metadata {
    name = "ebs-gp3"
    annotations = {
      "storageclass.kubernetes.io/is-default-class" = "true"
    }
  }

  storage_provisioner    = "ebs.csi.aws.com"
  volume_binding_mode    = "WaitForFirstConsumer"
  allow_volume_expansion = true

  parameters = {
    type      = "gp3"
    fsType    = "ext4"
    encrypted = "true"
  }

  depends_on = [aws_eks_addon.ebs_csi_driver]
}

resource "helm_release" "snapshot_controller" {
  name       = "snapshot-controller"
  repository = "piraeus"
  chart      = "snapshot-controller"
  version    = "4.0.2"
  namespace  = "kube-system"

  values = [
    yamlencode({
      controller = {
        replicaCount = 1
        # serviceMonitor = { # maybe add later if I want metrics
        #   create = true
        # }
      }
    })
  ]
}

resource "kubernetes_manifest" "csi_aws_vsc" {
  manifest = {
    apiVersion = "snapshot.storage.k8s.io/v1"
    kind       = "VolumeSnapshotClass"
    metadata = {
      name = "csi-aws-vsc"
      annotations = {
        "k10.kasten.io/is-snapshot-class" = "true"
      }
    }
    driver         = "ebs.csi.aws.com"
    deletionPolicy = "Delete"
  }

  depends_on = [aws_eks_addon.ebs_csi_driver]
}


resource "aws_eks_pod_identity_association" "aws_lbc" {
  cluster_name    = aws_eks_cluster.eks.name
  namespace       = "kube-system"
  service_account = "aws-load-balancer-controller"
  role_arn        = aws_iam_role.aws_lbc.arn
}

resource "helm_release" "aws_lbc" {
  name = "aws-load-balancer-controller"

  repository = "https://aws.github.io/eks-charts"
  chart      = "aws-load-balancer-controller"
  namespace  = "kube-system"
  version    = "1.13.4"

  set = [
    {
      name  = "clusterName"
      value = aws_eks_cluster.eks.name
    },
    {
      name  = "serviceAccount.name"
      value = "aws-load-balancer-controller"
    },
    {
      name  = "vpcId"
      value = aws_vpc.main.id
    }
  ]
}

resource "helm_release" "kasten-k10" {
  name             = "k10"
  repository       = "https://charts.kasten.io/"
  chart            = "k10"
  namespace        = "kasten-io"
  version          = "8.0.5"
  create_namespace = true

  values = [
    yamlencode({
      auth = {
        oidcAuth = {
          enabled          = true
          providerURL      = "https://authentik.chkpwd.com/application/o/kasten-k10/"
          redirectURL      = "http://localhost:8080"
          scopes           = "openid profile"
          prompt           = "select_account"
          clientSecretName = "kasten-k10-oidc"
          usernamePrefix   = "authentik-"
          usernameClaim    = "preferred_username"
          groupClaim       = "groups"
          logoutURL        = "https://authentik.chkpwd.com/application/o/kasten-k10/end-session/"
        }
        k10AdminUsers = ["authentik-chkpwd"]
      }

      rbac = {
        create = true
      }

      serviceAccount = {
        create = true
      }

      eula = {
        accept  = true
        company = "chkpwd"
        email   = "bryan@chkpwd.com"
      }

      secrets = {
        awsAccessKeyId     = aws_iam_access_key.kasten.id
        awsSecretAccessKey = aws_iam_access_key.kasten.secret
        awsIamRole         = aws_iam_role.kasten_k10.arn
      }

      externalGateway = {
        create = true
        annotations = {
          "service.beta.kubernetes.io/aws-load-balancer-type"            = "external"
          "service.beta.kubernetes.io/aws-load-balancer-scheme"          = "internet-facing"
          "service.beta.kubernetes.io/aws-load-balancer-nlb-target-type" = "ip"
        }
      }
    })
  ]
}

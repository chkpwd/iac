locals {
    # Get JSON for internal, kubernetes, and external configurations
    main       = jsondecode(file("${path.root}/../_templates/dns/infra_dns.json"))
    kubernetes = jsondecode(file("${path.root}/../_templates/dns/kubernetes_dns.json"))
    external   = jsondecode(file("${path.root}/../_templates/dns/external_svc.json"))

    # infra A Records
    infra_a = local.main.INFRA_A_RECORDS

    # kubernetes A Records
    kubernetes_a = local.kubernetes.KUBERNETES_A_RECORDS

    # external svc A Records
    external_a = local.external.EXTERNAL_A_RECORDS

    # infra CNAME Records
    infra_cname = local.main.INFRA_CNAME_RECORDS

    # kubernetes CNAME Records
    kubernetes_cname = local.kubernetes.KUBERNETES_CNAME_RECORDS

    # external svc CNAME Records
    external_cname = local.external.EXTERNAL_CNAME_RECORDS

}
locals {
    # get json 
    main = jsondecode(file("${path.root}/../_templates/dns/internal_dns.json"))

    # get all A Records
    type_a = local.main.A_RECORDS

    # Get all CNAME Records
    type_cname = local.main.CNAME_RECORDS
}
resource "oci_core_vcn" "orc" {
    compartment_id = "${data.sops_file.oci-secrets.data["oci_tenancy_ocid"]}"
    display_name  = "ORC-chkpwd"
    dns_label     = "chkpwd"
    cidr_blocks = [
        "10.53.0.0/16"
    ]
}

resource "oci_core_internet_gateway" "orc_ig" {
    compartment_id  = "${data.sops_file.oci-secrets.data["oci_tenancy_ocid"]}"
    vcn_id          = oci_core_vcn.orc.id
    display_name    = "ORC-IG"
    enabled         = true
}

resource "oci_core_route_table" "orc_routes" {
    compartment_id  = "${data.sops_file.oci-secrets.data["oci_tenancy_ocid"]}"
    vcn_id          = oci_core_vcn.orc.id
    display_name    = "ORC-RouteTable"
    route_rules {
        network_entity_id = oci_core_internet_gateway.orc_ig.id
        description       = "Default route"
        destination       = "0.0.0.0/0"
        destination_type  = "CIDR_BLOCK"
    }
}

resource "oci_core_subnet" "homelab" {
    cidr_block      = "10.53.20.0/24"
    compartment_id  = "${data.sops_file.oci-secrets.data["oci_tenancy_ocid"]}"
    vcn_id          = oci_core_vcn.orc.id
    display_name    = "Homelab"
    route_table_id  = oci_core_route_table.orc_routes.id
}
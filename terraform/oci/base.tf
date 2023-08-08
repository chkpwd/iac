resource "oci_core_vcn" "main" {
    compartment_id = "${data.sops_file.oci-secrets.data["oci_tenancy_ocid"]}"
    display_name  = "OCI-VCN"
    dns_label     = "chkpwd"
    cidr_blocks = [
        "10.53.0.0/16"
    ]
}

resource "oci_core_internet_gateway" "oci_ig" {
    compartment_id  = "${data.sops_file.oci-secrets.data["oci_tenancy_ocid"]}"
    vcn_id          = oci_core_vcn.main.id
    display_name    = "OCI-IG"
    enabled         = true
}

resource "oci_core_route_table" "oci_routes" {
    compartment_id  = "${data.sops_file.oci-secrets.data["oci_tenancy_ocid"]}"
    vcn_id          = oci_core_vcn.main.id
    display_name    = "OCI-RouteTable"
    route_rules {
        network_entity_id = oci_core_internet_gateway.oci_ig.id
        description       = "Default route"
        destination       = "0.0.0.0/0"
        destination_type  = "CIDR_BLOCK"
    }
}

resource "oci_core_subnet" "homelab" {
    cidr_block      = "10.53.20.0/24"
    compartment_id  = "${data.sops_file.oci-secrets.data["oci_tenancy_ocid"]}"
    vcn_id          = oci_core_vcn.main.id
    display_name    = "OCI-Subnet"
    dns_label       = "remote"
    route_table_id  = oci_core_route_table.oci_routes.id
}
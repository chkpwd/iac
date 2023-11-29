resource "oci_core_network_security_group_security_rule" "couchdb_port" {
    network_security_group_id = module.ct-02-x86.nsg_id
    direction = "INGRESS"
    protocol = "6"

    description = "Allow INGRESS from internal network"

    source = "10.53.0.0/16"
    source_type = "CIDR_BLOCK"
    stateless = false

    tcp_options {
        destination_port_range {
            #Required
            max = 5984
            min = 5984
        }
    }
}

resource "oci_core_network_security_group_security_rule" "zipline_port" {
    network_security_group_id = module.ct-02-x86.nsg_id
    direction = "INGRESS"
    protocol = "6"

    description = "Allow INGRESS from internal network"

    source = "10.53.0.0/16"
    source_type = "CIDR_BLOCK"
    stateless = false

    tcp_options {
        destination_port_range {
            #Required
            max = 3000
            min = 3000
        }
    }
}

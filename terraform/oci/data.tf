data "oci_core_vcn" "main" {
  vcn_id = oci_core_vcn.main.id
}

data "oci_core_subnet" "main" {
  subnet_id = oci_core_subnet.homelab.id
}

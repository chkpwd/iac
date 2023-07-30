preseed             = "k3s"
os_iso_url          = "https://cdimage.debian.org/debian-cd/current/amd64/iso-cd/debian-12.0.0-amd64-netinst.iso"
iso_checksum        = "3b0e9718e3653435f20d8c2124de6d363a51a1fd7f911b9ca0c6db6b3d30d53e"
iso_checksum_type   = "sha256"
num_cores           = "1"
mem_size            = "1024"
root_disk_size      = "32000"
guest_os_type       = "otherLinux64Guest"
machine_name        = "k3s-deb12"
domain              = "local.chkpwd.com"
connection_username = "hyoga"
hostname            = "k3s-deb12"
ssh_public_key      = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBK2VnKgOX7i1ISETheqjAO3/xo6D9n7QbWyfDAPsXwa crypto"
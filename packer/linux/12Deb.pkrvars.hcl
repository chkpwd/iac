preseed             = "k3s"
os_iso_url          = "https://cdimage.debian.org/debian-cd/current/amd64/iso-cd/debian-12.2.0-amd64-netinst.iso"
iso_checksum        = "23ab444503069d9ef681e3028016250289a33cc7bab079259b73100daee0af66"
iso_checksum_type   = "sha256"
num_cores           = "1"
mem_size            = "1024"
root_disk_size      = "16000"
guest_os_type       = "debian12_64Guest"
machine_name        = "deb-12-template"
domain              = "local.chkpwd.com"
hostname            = "deb-12-template"
ssh_public_key      = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBK2VnKgOX7i1ISETheqjAO3/xo6D9n7QbWyfDAPsXwa crypto"

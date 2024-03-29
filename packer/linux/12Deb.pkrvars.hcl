preseed             = "debian12"
os_iso_url          = "https://cdimage.debian.org/debian-cd/current/amd64/iso-cd/debian-12.4.0-amd64-netinst.iso" # renovate: datasource=custom.debian depName=debian
iso_checksum        = "013f5b44670d81280b5b1bc02455842b250df2f0c6763398feb69af1a805a14f"
iso_checksum_type   = "sha256"
num_cores           = "1"
mem_size            = "1024"
root_disk_size      = "16000"
vhd_controller_type = ["pvscsi"]
guest_os_type       = "debian12_64Guest"
machine_name        = "deb-12-template"
domain              = "local.chkpwd.com"
hostname            = "deb-12-template"
ssh_public_key      = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBK2VnKgOX7i1ISETheqjAO3/xo6D9n7QbWyfDAPsXwa"

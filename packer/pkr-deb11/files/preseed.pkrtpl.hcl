# Setting the locales, country
# Supported locales available in /usr/share/i18n/SUPPORTED
d-i debian-installer/language string en_GB
d-i debian-installer/country string GB

# User creation
d-i passwd/user-fullname string ${user_fullname}
d-i passwd/username string ${user_name}
d-i passwd/user-uid string 1000
d-i passwd/user-password password ${user_password}
d-i passwd/user-password-again password ${user_password}
d-i user-setup/allow-password-weak boolean true

# Clock and Timezone
d-i clock-setup/utc boolean true
d-i clock-setup/ntp boolean true
d-i time/zone string Europe/London

# Disk and Partitioning setup
d-i partman-auto/disk string /dev/nvme0n1
d-i partman-auto-lvm/guided_size string max
d-i partman-auto/choose_recipe select atomic
d-i partman-auto/method string regular
d-i partman-lvm/confirm boolean true
d-i partman-lvm/confirm boolean true
d-i partman-lvm/confirm_nooverwrite boolean true
d-i partman-lvm/device_remove_lvm boolean true
d-i partman/choose_partition select finish
d-i partman/confirm boolean true
d-i partman/confirm_nooverwrite boolean true
d-i partman-partitioning/choose_label string gpt
d-i partman-partitioning/default_label string gpt
d-i partman/confirm_write_new_label boolean true
d-i partman-efi/non_efi_system boolean true

# GRUB
d-i grub-installer/only_debian boolean true
d-i grub-installer/bootdev string /dev/nvme0n1

# Disable scanning install image (because netinst)
d-i apt-setup/cdrom/set-first boolean false
d-i apt-setup/cdrom/set-next boolean false
d-i apt-setup/cdrom/set-failed boolean false

# Set mirror
d-i mirror/country string manual GB
d-i mirror/http/hostname string deb.debian.org
d-i mirror/http/directory string /debian

# Set root password
d-i passwd/root-login boolean false
d-i passwd/root-password password 
d-i passwd/root-password-again password 

# Package installations
popularity-contest popularity-contest/participate boolean false
d-i pkgsel/run_tasksel boolean false
d-i pkgsel/include string openssh-server open-vm-tools python3-apt
d-i pkgsel/install-language-support boolean false
d-i pkgsel/update-policy select none
d-i pkgsel/upgrade select full-upgrade

d-i finish-install/reboot_in_progress note

# Fix EFI boot
d-i preseed/late_command string in-target grub-install --removable --force

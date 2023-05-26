### Setting the locales, country
d-i debian-installer/locale string en_US
d-i keyboard-configuration/xkb-keymap select us
d-i console-setup/ask_detect boolean false
choose-mirror-bin mirror/http/proxy string

### Clock
d-i clock-setup/utc boolean true
d-i time/zone string America/New_York
d-i netcfg/choose_interface select auto

### Host
d-i netcfg/get_domain string local.chkpwd.com
d-i netcfg/hostname string deb-x11-template
d-i netcfg/wireless_wep string

### Account setup - Root
d-i passwd/root-password password 
d-i passwd/root-password-again password 

### Account setup - Normal
d-i passwd/user-fullname string ${user_fullname}
d-i passwd/username string ${user_name}
d-i passwd/user-password password ${user_password}
d-i passwd/user-password-again password ${user_password}
d-i passwd/user-uid string 1000

### Mirror settings
# If you select ftp, the mirror/country string does not need to be set.
d-i mirror/country string manual
d-i mirror/http/hostname string http.us.debian.org
d-i mirror/http/directory string /debian
d-i mirror/http/proxy string


################################################################## ]]]
## Disk Partitioning/Boot loader [[[
######################################################################

# If the system has only one disk the installer will default to using it.
# Otherwise, the device name must be given
d-i partman-auto/disk                           string  /dev/sda

d-i partman-auto/init_automatically_partition   select  custom

# Specify the method to use
# - regular: use the usual partition types for the architecture
# - lvm: use LVM to partition the disk
# - crypto: use LVM within an encrypted partition
#d-i partman-auto/method string regular
d-i partman-auto/method                         string  lvm

d-i partman-lvm/device_remove_lvm               boolean true

# It's ok to have /boot in the LVM
d-i partman-auto-lvm/no_boot                    boolean false

# Remove old LVM configuration
d-i partman-lvm/device_remove_lvm               boolean true
d-i partman-lvm/device_remove_lvm_span          boolean true
d-i partman-auto/purge_lvm_from_device          boolean true
# Remove old RAID configuration
#d-i partman-md/device_remove_md boolean true
# Confirm to write the LVM partitions
d-i partman-lvm/confirm                         boolean true
d-i partman-lvm/confirm_nooverwrite             boolean true

# Keep that one set to true so we end up with a UEFI enabled
# system. If set to false, /var/lib/partman/uefi_ignore will be touched
d-i partman-efi/non_efi_system boolean true

# enforce usage of GPT - a must have to use EFI!
d-i partman-basicfilesystems/choose_label       string  gpt
d-i partman-basicfilesystems/default_label      string  gpt
d-i partman-partitioning/choose_label           string  gpt
d-i partman-partitioning/default_label          string  gpt
d-i partman/choose_label                        string  gpt
d-i partman/default_label                       string  gpt
partman-basicfilesystems partman-basicfilesystems/no_swap boolean false
# LVM partition
# This recipe need almost 30Gb free space it's add all <min size>
# Allow to not set a swap partition
# Disk and Partitioning setup
d-i partman-auto/disk string /dev/sda
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

#d-i partman-basicfilesystems/no_swap              boolean false

# Automatically partition without confirmation
d-i   partman/confirm_write_new_label             boolean true
d-i   partman/choose_partition                    select  finish
d-i   partman-md/confirm                          boolean true
d-i   partman/confirm                             boolean true
d-i   partman/confirm_nooverwrite                 boolean true

#d-i apt-setup/cdrom/set-first boolean false

# The installer will warn about weak passwords. If you are sure you know
# what you're doing and want to override it, uncomment this.
d-i user-setup/allow-password-weak boolean true
d-i user-setup/encrypt-home boolean false

### Package selection
tasksel tasksel/first multiselect standard
d-i pkgsel/include string openssh-server build-essential open-vm-tools vim
d-i pkgsel/install-language-support boolean false

# disable automatic package updates
d-i pkgsel/update-policy select none
d-i pkgsel/upgrade select full-upgrade

d-i grub-installer/only_debian boolean true
d-i grub-installer/with_other_os boolean true
d-i grub-installer/bootdev string /dev/sda

# ignore the completion message
d-i finish-install/reboot_in_progress note

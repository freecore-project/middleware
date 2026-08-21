#!/bin/sh
# FreeCORE adaptation of Victor Tschetter's installer; see FREECORE-NOTES.md.
set -e

if [ "$(id -u)" != 0 ]; then
    echo "This script must be run with root privileges."
    exit 1
fi

pkg install -y adguardhome

# FreeCORE verifies both writable persistent mounts before running this script.
test -d /usr/local/etc/adguardhome
test -d /var/db/adguardhome

# Older installations may have a config in the former package location.
# Current packages supply no YAML: AdGuard Home initializes it during setup.
if [ ! -f /usr/local/etc/adguardhome/AdGuardHome.yaml ] && [ -f /usr/local/etc/AdGuardHome.yaml ]; then
    cp /usr/local/etc/AdGuardHome.yaml /usr/local/etc/adguardhome/AdGuardHome.yaml
fi

# Match the pinned FreeCORE port's account for the privileged DNS port.
# These settings apply only inside the jail; dataset ownership is preserved.
sysrc adguardhome_enable=YES
sysrc adguardhome_user=root
sysrc adguardhome_group=wheel
sysrc adguardhome_config=/usr/local/etc/adguardhome/AdGuardHome.yaml
sysrc adguardhome_work_dir=/var/db/adguardhome
# The package uses daemon(8). Detach its supervisor from the job's output
# pipes so template execution finishes while service logging remains enabled.
sysrc adguardhome_flags=-f
service adguardhome restart

echo "AdGuard Home service restarted."
echo "New installations use the setup page on port 3000. Existing configuration is retained."

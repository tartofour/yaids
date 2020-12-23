#!/usr/bin/bash

echo "Désinstallation de yaids..."
systemctl stop yaids
systemctl disable yaids
rm /usr/local/bin/yaids
rm /etc/systemd/system/yaids.service
rm -rf /etc/yaids/

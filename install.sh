#!/usr/bin/bash

echo "Installation de yaids..."
cp -f ./yaids /usr/local/bin/
chmod +x /usr/local/bin/yaids
cp -f ./yaids.service /etc/systemd/system/
chmod 640 /etc/systemd/system/yaids.service
mkdir -p /etc/yaids
cp -f ./rules.txt /etc/yaids/
systemctl daemon-reload
systemctl enable yaids
systemctl start yaids

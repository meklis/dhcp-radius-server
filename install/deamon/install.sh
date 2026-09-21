#!/bin/bash

VERSION=0.0.1
CONF_FILE=/etc/dhcp-radius-server/radis.server.conf.yml

echo "Installing dhcp-radius-server, ver. $VERSION"

if [ -e "$CONF_FILE" ]; then
  echo "Defined old configuration $CONF_FILE, file not be updated"
  echo "Example of new configuration file will be saved to /etc/dhcp-radius-server/example.radis.server.conf.yml"
  CONF_FILE=/etc/dhcp-radius-server/example.radis.server.conf.yml
else
  CONF_FILE=/etc/dhcp-radius-server/radis.server.conf.yml
fi

echo "Creating destination directory..."
mkdir -p /etc/dhcp-radius-server
mkdir -p /usr/local/bin

echo "Downloading binaries..."
rm /tmp/dhcp-radius-server
wget -O /tmp/dhcp-radius-server https://github.com/meklis/dhcp-radius-server/releases/download/$VERSION/dhcp-radius-server
STATUS_BIN=$?
wget -O "$CONF_FILE" https://raw.githubusercontent.com/meklis/dhcp-radius-server/$VERSION/radis.server.conf.yml
STATUS_CONF=$?

if  [ $STATUS_BIN -eq 0 ] && [ $STATUS_CONF -eq 0 ]
then
  echo "Success download! Install..."
  echo "Check status of service"
  systemctl status all-ok-radius && systemctl stop all-ok-radius && rm /usr/local/bin/dhcp-radius-server
  mv /tmp/dhcp-radius-server /usr/local/bin/dhcp-radius-server
  chmod +x /usr/local/bin/dhcp-radius-server
else
  echo "Failed download binaries"
  exit 2
fi

echo ""
echo "Register service in systemd..."
echo "
[Unit]
Description=Proxy with round robin interfaces
After=network.target
StartLimitIntervalSec=0
[Service]
Type=simple
Restart=always
RestartSec=1
User=root
LimitNOFILE=128000
ExecStart=/usr/local/bin/dhcp-radius-server -c /etc/dhcp-radius-server/radis.server.conf.yml
[Install]
WantedBy=multi-user.target
" > /etc/systemd/system/all-ok-radius.service

systemctl enable all-ok-radius

echo "Installation finished!"
echo "Service not started automaticaly"
echo "Command for get service status:"
echo "    systemctl status all-ok-radius"
echo ""
echo "Command for start service:"
echo "    systemctl start all-ok-radius"

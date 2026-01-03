#!/bin/bash
ORIGINAL_DIR=$(pwd)

sudo apt update
sudo apt-get install -y curl wget unzip tcpdump gnupg lsb-release build-essential git htop libpcap-dev python3-requests python3-pyinotify

cd /opt
sudo wget -O tzsp2pcap-master.zip https://github.com/thefloweringash/tzsp2pcap/archive/master.zip
sudo unzip -o tzsp2pcap-master.zip
cd tzsp2pcap-master/
sudo make
sudo make install

cd /opt
sudo wget https://github.com/appneta/tcpreplay/releases/download/v4.4.2/tcpreplay-4.4.2.tar.gz
sudo tar -xf tcpreplay-4.4.2.tar.gz
cd tcpreplay-4.4.2/
sudo ./configure
sudo make
sudo make install

sudo cp "$ORIGINAL_DIR/tzsp0.netdev" /etc/systemd/network/
sudo cp "$ORIGINAL_DIR/tzsp0.network" /etc/systemd/network/

sudo systemctl enable systemd-networkd
sudo systemctl restart systemd-networkd

sudo cp "$ORIGINAL_DIR/TZSPreplay@.service" /etc/systemd/system/

sudo systemctl daemon-reload
sudo systemctl enable --now TZSPreplay@tzsp0.service

systemctl status TZSPreplay@tzsp0.service --no-pager

sudo apt-get install suricata
sudo suricata-update
sudo systemctl restart suricata

sudo cp "$ORIGINAL_DIR/mikrotik2suricata.py" /usr/local/bin
sudo cp "$ORIGINAL_DIR/mikrotik2suricatabridge.service" /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now mikrotik2suricatabridge.service.service

echo "================= INSTALATION COMPLETE ================="
echo "Please change your token in /usr/local/bin/mikrotik2suricata.py"
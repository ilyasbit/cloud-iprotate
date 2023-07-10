#!/bin/bash

apt update -y
apt install -y tar screen wget curl nano htop git net-tools --no-install-recommends

if ! node -v | grep -q "v18"; then
    curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
    apt update -y
    apt install -y nodejs
    npm install -g n
    npm install -g pm2
    n 18
else
    echo "nodejs version 18.x.x already installed"
fi

if [[ -d "/opt/cloud-iprotate/" ]]; then
    rm -rf /opt/cloud-iprotate/
fi
sudo curl https://raw.githubusercontent.com/ilyasbit/ss-easy-setup/main/install-only.sh | sudo bash -s
mkdir -p /etc/shadowsocks/
rm -rf cloud-iprotate/
git clone https://github.com/ilyasbit/cloud-iprotate.git -b dev

useradd iprotate
mkdir -p /home/iprotate/.ssh
sudo usermod -aG nogroup iprotate
ssh-keygen -t ed25519 -f /home/iprotate/.ssh/id_rsa -N ""
cat /home/iprotate/.ssh/id_rsa.pub | cut -d " " -f1,2 >/home/iprotate/.ssh/authorized_keys
chown -R iprotate:iprotate /home/iprotate/.ssh/

mv cloud-iprotate /opt/
cd /opt/cloud-iprotate/
npm install
cd ~

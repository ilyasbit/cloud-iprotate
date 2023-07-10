#!/bin/bash

useradd iprotate
mkdir -p /home/iprotate/.ssh
sudo usermod -aG nogroup iprotate
ssh-keygen -t ed25519 -f /home/iprotate/.ssh/id_rsa -N ""
cat /home/iprotate/.ssh/id_rsa.pub | cut -d " " -f1,2 >/home/iprotate/.ssh/authorized_keys
chown -R iprotate:iprotate /home/iprotate/.ssh/

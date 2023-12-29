#!/bin/bash

sudo fallocate -l 5G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
# Active on sistem boot.
echo -e '$(sudo blkid -o export /swapfile | rep UUID) none swap sw 0 0' | sudo tee -a /etc/fstab 
# Swappiness to 80.
sudo sed -i '/^vm.swappiness =/s/^vm.swappiness = .*/vm.swappiness = 80/' /etc/sysctl.conf
sudo sysctl -p
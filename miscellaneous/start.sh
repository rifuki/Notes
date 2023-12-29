#!/bin/bash

if [ -e ../.env.example ]; then
    echo '.env.example found!'
    echo 'Rename .env.example to .env'
    mv .env.example .env
fi
if [ -e ../.env ]; then
    echo '.env found!'
    source .env
else
    echo 'Please set .env first!' 
    exit 1
fi

sudo apt update

# Docker
if [ -e '/etc/apt/keyrings/docker.gpg' ]; then
    sudo apt install ca-certificates curl gnupg -y
    sudo install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    sudo chmod a+r /etc/apt/keyrings/docker.gpg

    echo \
    "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
    $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
    sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
    sudo apt update

    sudo apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin -y

    sudo docker run hello-world
if

# Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -- -y
source '$HOME/.cargo/env'

# Reverse Proxy
sudo apt install nginx -y
sudo apt install certbot python3-certbot-nginx -y
sudo cp ./actix /etc/nginx/sites-available/
sudo ln -s /etc/nginx/sites-available/actix /etc/nginx/sites-enabled/actix

sudo certbot --nginx -d actix.notes.rifuki.xyz www.actix.notes.rifuki.xyz
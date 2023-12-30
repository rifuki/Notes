#!/bin/bash

if [ -f .env.example ]; then
    echo '.env.example found!'
    if ! [ -f .env ]; then
        echo 'Clone .env.example to .env'
        cp .env.example .env
    else
        echo '.env found!'
    fi
fi

# Docker
if ! [ -f /usr/bin/docker  ]; then
    sudo apt install ca-certificates curl gnupg -y
    sudo install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    sudo chmod a+r /etc/apt/keyrings/docker.gpg

    echo \
    "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
    $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
    sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
    sudo apt update

    sudo apt install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin -y

    sudo docker run hello-world
fi

# Rust
if ! [ -e $HOME/.cargo ]; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
fi

# Reverse Proxy
if ! [ -f /usr/sbin/nginx ]; then
    sudo apt install nginx -y
fi

if ! [ -f /etc/nginx/sites-available/actix ]; then
    sudo cp ./miscellaneous/actix /etc/nginx/sites-available/
    sudo ln -s /etc/nginx/sites-available/actix /etc/nginx/sites-enabled/
fi
if ! [ -f /etc/nginx/sites-available/pgadmin ]; then
    sudo cp ./miscellaneous/pgadmin /etc/nginx/sites-available/
    sudo ln -s /etc/nginx/sites-available/pgadmin /etc/nginx/sites-enabled/
fi

if ! [ -f /usr/bin/certbot ]; then
    sudo apt remove certbot -y
    sudo apt install snapd -y
    sudo snap install core
    sudo snap refresh core
    sudo snap install --classic certbot
    sudo ln -s /snap/bin/certbot /usr/bin/certbot
fi

if ! [ -f /etc/letsencrypt/renewal/actix.notes.rifuki.xyz.conf ]; then 
    sudo certbot --nginx -d actix.notes.rifuki.xyz -d www.actix.notes.rifuki.xyz
fi
if ! [ -f /etc/letsencrypt/renewal/pgadmin.notes.rifuki.xyz.conf ]; then
    sudo certbot --nginx -d pgadmin.notes.rifuki.xyz -d www.pgadmin.notes.rifuki.xyz
    sudo systemctl restart nginx
fi

ufw_status=$(sudo ufw status)
if [[ $ufw_status != *"Status: active"* ]]; then
    # echo "y" | sudo ufw enable
    yes | sudo ufw enable
    sudo ufw allow 'OpenSSH'
    sudo ufw allow 'Nginx Full'
    sudo ufw status
else
    echo "UFW already active."
fi
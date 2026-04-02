# TOR_Python

# TODO FIX ENCRYPTION WITH DOCKER

# DOCKER:
docker compose up --build entry middle exit
docker compose run --build client

# ALIAS SETUP FOR DOCKER BUILD (Unix):
sudo ip addr add 127.20.0.2/24 dev lo
sudo ip addr add 127.20.0.2/24 dev lo
sudo ip addr add 127.20.0.2/24 dev lo

# ALIAS SETUP FOR DOCKER BUILD (mac):
sudo ifconfig lo0 alias 127.20.0.2 up
sudo ifconfig lo0 alias 127.20.0.3 up
sudo ifconfig lo0 alias 127.20.0.4 up


# Setup Alias IPs for Relay

## Linux
sudo ip addr add 127.0.0.2/8 dev lo
sudo ip addr add 127.0.0.3/8 dev lo
sudo ip addr add 127.0.0.4/8 dev lo

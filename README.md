# TOR_Python

# BUILDING WITH DOCKER:
docker compose build
docker compose up entry middle exit
docker compose run --rm client


# Setup Alias IPs for Relay

## Linux
sudo ip addr add 127.0.0.2/8 dev lo
sudo ip addr add 127.0.0.3/8 dev lo
sudo ip addr add 127.0.0.4/8 dev lo

# TOR_Python

# Requires docker, docker compose (or docker-compose), and pytest

# IF you are using docker desktop, please open the desktop application before
# running the commands below


# BUILDING & RUNNING WITH DOCKER:
docker compose build
docker compose up entry middle exit
docker compose run --rm client

# If you are using the legacy version of docker compose, you may need to 
# use "docker-compose" in the above commands

# INTEGRATION TEST:
pytest test_integration.py

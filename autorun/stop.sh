#!/bin/bash

# Load env
. config.env
export HOST_PATH="$(cd .. && pwd)/"
export BASE_PATH="$(cd ../.. && pwd)/"

# Stop all service
echo "Stopping all services ..."
IFS=',' read -r -a E <<< "$SERVICES"

for i in "${E[@]}";
do
    echo "Stopping $i""-service ..."
    cd "$BASE_PATH""$i""-service/$DOCKER_DIR"
    docker-compose -f dev.docker-compose.yml stop
done
echo "Done."
echo "Then stopping database, cacher, transporter, api gateways ..."

cd "$HOST_PATH$DOCKER_DIR"
docker-compose -f dev.docker-compose.yml stop

cd "$BASE_PATH"
cd client-api-gateway/docker
docker-compose -f dev.docker-compose.yml stop

echo "Stopped all services."

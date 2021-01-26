#!/bin/bash

. config.env
#stop the service
export BASE_DIR="$(dirname "$(dirname "$(pwd)")")/"

echo "Stop all services"
IFS=',' read -r -a E <<< "$SERVICES"

for i in "${E[@]}";
do
    echo "Stop $i""-service"
    cd "$BASE_DIR""$i""-service/$DOCKER_DIR"
    docker-compose -f dev.docker-compose.yml  down
done
echo "Then stop database, cacher, transporter"

cd "$BASE_DIR$HOST_DIR$DOCKER_DIR"
docker-compose -f dev.docker-compose.yml down

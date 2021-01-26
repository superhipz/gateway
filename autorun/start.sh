#!/bin/bash
./stop.sh

. config.env
export HOST_PATH="$(cd .. && pwd)/"
export BASE_PATH="$(cd ../.. && pwd)/"

# Start host-api-gateway
echo "Starting database, cacher, transporter of api gateways ..."
cd "$HOST_PATH$DOCKER_DIR"
docker-compose -f dev.docker-compose.yml build "host-api-gateway"
npm run dc:up

# Start client-api-gateway
cd "$BASE_PATH"
cd client-api-gateway/docker
docker-compose -f dev.docker-compose.yml build client-api-gateway
docker-compose -f dev.docker-compose.yml up -d client-api-gateway

# Start admin-api-gateway
cd "$BASE_PATH"
cd admin-api-gateway/docker
docker-compose -f dev.docker-compose.yml build admin-api-gateway
docker-compose -f dev.docker-compose.yml up -d admin-api-gateway

PGPASSWORD="node@node" docker exec dev-postgres createdb -h "localhost" -p "5432" -U "super_node" "admin_api_dev" || echo "admin_api_dev DB already exists"

echo "Wait 2 second for ready process process "
sleep 2

echo "Starting other services ..."
IFS=',' read -r -a E <<< "$SERVICES"

for i in "${E[@]}";
do
    echo "Starting $i""-service ..."
    cd "$BASE_PATH""$i""-service/$DOCKER_DIR"
    PGPASSWORD="$DB_PASSWORD" createdb -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" "$i""_dev" || echo "DB already exists"

    docker-compose -f dev.docker-compose.yml  build "$i"-service
    docker-compose -f dev.docker-compose.yml  up -d "$i"-service
done
echo "Done."

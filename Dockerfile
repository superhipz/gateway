FROM node:12.16.3-alpine

ENV NODE_ENV=production

RUN mkdir /app
WORKDIR /app

COPY package.json package-lock.json ./

RUN npm i --production

COPY . .

CMD docker/entrypoint.sh

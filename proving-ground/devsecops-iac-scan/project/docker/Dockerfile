FROM node:20-bookworm-slim

WORKDIR /srv/app
COPY package.json ./
RUN npm install --omit=dev --ignore-scripts
COPY index.js ./

EXPOSE 8080
CMD ["node", "index.js"]

# The bundled Node + Postgres practice target. Built on the host before the range is sealed
# (HC-SUB-01 §13: image dependencies that need the network are resolved in a pre-lockdown build,
# never during a live engagement), then run inside the egress-denied range with no network of
# its own. node:20-alpine carries sh, which the sandbox's marker helpers use for the G3/G5 drills.
FROM node:20-alpine
WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev
COPY server.js ./
EXPOSE 3000
CMD ["node", "server.js"]

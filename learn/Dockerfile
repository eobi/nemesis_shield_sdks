# Nemesis Learn - zero-dependency Node CLI. Run against a local app with --network host.
#   docker build -t nemesis-learn .
#   docker run --rm --network host nemesis-learn --target http://localhost:3000
FROM node:20-alpine
# git lets --repo accept a remote URL (clone --depth 1)
RUN apk add --no-cache git
WORKDIR /app
COPY package.json ./
COPY src ./src
ENTRYPOINT ["node", "src/index.mjs"]

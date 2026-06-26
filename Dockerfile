FROM node:20-alpine

WORKDIR /app

# Install production deps first for better layer caching.
COPY package.json ./
RUN npm install --omit=dev

COPY server ./server
COPY public ./public

ENV NODE_ENV=production
EXPOSE 3000

CMD ["node", "server/index.js"]

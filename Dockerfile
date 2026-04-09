FROM node:18-alpine
WORKDIR /app
COPY proxy.js .
CMD ["node", "proxy.js"]

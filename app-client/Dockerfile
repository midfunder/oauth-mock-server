FROM node:16.8.0 as builder

ARG REACT_APP_AUTH_DOMAIN
ARG REACT_APP_AUTH_CLIENT_ID
ARG REACT_APP_AUTH_AUDIENCE
ARG REACT_APP_API_URL

WORKDIR /workspace
ENV NODE_ENV=production
COPY package.json tsconfig.json yarn.lock ./
RUN yarn install
COPY src ./src
COPY public ./public
RUN yarn build

FROM nginx:1.20.1
COPY --from=0 /workspace/build /var/www/html/
COPY nginx.conf /etc/nginx/

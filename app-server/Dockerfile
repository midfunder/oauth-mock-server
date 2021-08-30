FROM node:16.8.0 as builder
RUN npm i -g @nestjs/cli
WORKDIR /workspace
COPY package.json tsconfig.json tsconfig.build.json yarn.lock ./
ENV NODE_ENV=production
ENV PORT=80
RUN yarn install
COPY src ./src
RUN yarn build
EXPOSE 80
CMD [ "node", "dist/main" ]
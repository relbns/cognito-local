FROM node:22-alpine AS builder
WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts

COPY src src
COPY tsconfig.json tsconfig.build.json ./

RUN npx esbuild src/bin/start.ts --outdir=lib --platform=node --target=node22 --bundle

FROM node:22-alpine
ARG VERSION=dev
ARG REVISION=unknown
LABEL org.opencontainers.image.title="cognito-emulator" \
      org.opencontainers.image.description="Local emulator of the Amazon Cognito User Pools API" \
      org.opencontainers.image.source="https://github.com/relbns/cognito-local" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"

WORKDIR /app
COPY --from=builder --chown=root:root /app/lib .
RUN mkdir -p /app/.cognito && chown node:node /app/.cognito

ENV HOST=0.0.0.0 \
    PORT=9229 \
    NODE_ENV=production
EXPOSE 9229
VOLUME /app/.cognito
USER node

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -qO- "http://127.0.0.1:${PORT}/health" >/dev/null || exit 1

ENTRYPOINT ["node", "/app/start.js"]

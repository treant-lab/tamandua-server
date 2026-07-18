# Tamandua Server - release image
#
# Keep this file aligned with deploy/docker/Dockerfile.server. The lab-light
# deploy script copies that Dockerfile into this path before remote builds, but
# direct builds from apps/tamandua_server must also produce a release image.

FROM elixir:1.16-otp-26-alpine AS builder

ARG MIX_ENV=prod
ARG NODE_ENV=production
ARG WARNINGS_AS_ERRORS=false
ARG SKIP_ASSETS_BUILD=false

ENV MIX_ENV=${MIX_ENV} \
    NODE_ENV=${NODE_ENV} \
    LANG=C.UTF-8 \
    ERL_FLAGS="+S 1:1 +sbwt none +sbwtdcpu none +sbwtdio none" \
    HEX_HTTP_TIMEOUT=120000 \
    HEX_HTTP_CONCURRENCY=1

RUN apk add --no-cache \
    build-base \
    git \
    nodejs \
    npm \
    python3 \
    curl \
    openssl-dev

WORKDIR /app

RUN mix local.hex --force && \
    mix local.rebar --force

COPY mix.exs mix.lock ./
COPY config/config.exs config/prod.exs config/

RUN mix deps.get --only ${MIX_ENV}
RUN mix deps.compile

COPY assets/package.json assets/package-lock.json assets/
RUN if [ "$SKIP_ASSETS_BUILD" = "true" ]; then \
      echo "Skipping npm install; using prebuilt priv/static assets"; \
    else \
      cd assets && npm ci --production=false; \
    fi

COPY assets assets
RUN if [ "$SKIP_ASSETS_BUILD" = "true" ]; then \
      echo "Skipping frontend build; using prebuilt priv/static assets"; \
    else \
      cd assets && npm run build; \
    fi

COPY priv priv
COPY lib lib
COPY config/runtime.exs config/

RUN if [ "$WARNINGS_AS_ERRORS" = "true" ]; then \
      ERL_FLAGS="+S 1:1 +sbwt none +sbwtdcpu none +sbwtdio none" mix compile --warnings-as-errors; \
    else \
      ERL_FLAGS="+S 1:1 +sbwt none +sbwtdcpu none +sbwtdio none" mix compile; \
    fi

RUN if [ "$SKIP_ASSETS_BUILD" = "true" ]; then \
      echo "Skipping phx.digest; using pre-digested priv/static assets"; \
      test -s priv/static/assets/manifest.json; \
      test -s priv/static/cache_manifest.json; \
    else \
      mix phx.digest; \
    fi

RUN ERL_FLAGS="+S 1:1 +sbwt none +sbwtdcpu none +sbwtdio none" mix release

FROM alpine:3.24 AS runtime

ARG APP_VERSION=0.1.0
ARG INSTALL_CHROMIUM=true

LABEL org.opencontainers.image.title="Tamandua Server" \
      org.opencontainers.image.description="Tamandua EDR Backend Server" \
      org.opencontainers.image.version="${APP_VERSION}" \
      org.opencontainers.image.vendor="Treant Lab" \
      org.opencontainers.image.source="https://github.com/treant-lab/tamandua-community" \
      org.opencontainers.image.licenses="Apache-2.0" \
      io.tamandua.component="backend"

RUN apk add --no-cache \
    libstdc++ \
    openssl \
    ncurses-libs \
    libgcc \
    curl \
    postgresql-client \
    tini \
    && if [ "$INSTALL_CHROMIUM" = "true" ]; then apk add --no-cache chromium; fi \
    && rm -rf /var/cache/apk/*

RUN addgroup -g 1000 tamandua && \
    adduser -u 1000 -G tamandua -h /app -D tamandua

WORKDIR /app

COPY --from=builder --chown=tamandua:tamandua /app/_build/prod/rel/tamandua_server ./
RUN test -x /app/bin/tamandua_server
COPY --chown=tamandua:tamandua priv/yara_rules ./priv/yara_rules
COPY --chown=tamandua:tamandua priv/sigma_rules ./priv/sigma_rules

RUN mkdir -p /app/tmp /app/logs && \
    chown tamandua:tamandua /app/tmp /app/logs

USER tamandua

ENV HOME=/app \
    PHX_SERVER=true \
    LANG=C.UTF-8 \
    RELEASE_TMP=/app/tmp \
    RELEASE_COOKIE=${RELEASE_COOKIE:-tamandua_secret_cookie}

HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:4000/api/v1/health || exit 1

EXPOSE 4000

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["bin/tamandua_server", "start"]

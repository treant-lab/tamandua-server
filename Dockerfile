FROM elixir:1.16-alpine

# Install build dependencies and minimal runtime tools needed by the lab-light bootstrap.
# OpenSSL is required at runtime by the PKI/CSR enrollment path.
RUN apk add --no-cache build-base git python3 inotify-tools npm nodejs postgresql-client curl openssl

WORKDIR /app

# Install hex + rebar
RUN mix local.hex --force && \
    mix local.rebar --force

# Set env
ENV MIX_ENV=prod
ENV GUARDIAN_SECRET_KEY=dev_secret_key_change_in_production
ENV SECRET_KEY_BASE=dev_secret_key_base_change_in_production_min_64_chars_required_here
ENV ERL_COMPILER_OPTIONS=nowarn_unused_vars

# Copy mix/config files first for better dependency caching.
COPY mix.exs ./
COPY mix.lock ./
COPY config ./config/

RUN mix deps.get --only prod
RUN mix deps.compile

# Copy priv (migrations, etc)
COPY priv ./priv/

# Install frontend dependencies before copying the whole asset tree so UI-only
# rebuilds can reuse the npm dependency layer.
COPY assets/package*.json ./assets/
RUN npm ci --prefix assets --no-audit --no-fund \
    --fetch-retries=5 \
    --fetch-retry-mintimeout=20000 \
    --fetch-retry-maxtimeout=120000

COPY assets ./assets/

# Copy lib
COPY lib ./lib/

RUN mix compile

# Build the Phoenix/Tailwind assets used by non-Inertia pages such as login and
# registration, then build the React/Inertia frontend with Vite. Running both
# pipelines keeps /assets/app.css and /assets/app.js valid while still publishing
# the hashed React shell assets consumed by the app console.
RUN mix assets.deploy
RUN sh -lc "cd assets && npx vite build"
RUN mix phx.digest

EXPOSE 4000

CMD ["mix", "phx.server"]

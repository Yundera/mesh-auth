FROM node:lts AS base
ENV PNPM_HOME="/pnpm"
ENV PATH="$PNPM_HOME:$PATH"
RUN corepack enable
RUN corepack prepare pnpm@9.9.0 --activate

WORKDIR /app
COPY package.json /app
COPY pnpm-lock.yaml /app
COPY .npmrc /app

FROM base AS prod-deps
RUN --mount=type=cache,id=pnpm,target=/pnpm/store pnpm install --prod --frozen-lockfile

FROM base AS build
RUN --mount=type=cache,id=pnpm,target=/pnpm/store pnpm install --frozen-lockfile
COPY . /app
RUN pnpm run build

FROM base
# The registrar shells out to register-oidc-client.sh (mounted from template-root),
# which invokes `docker run authelia/authelia ...` for argon2 hashing. We need
# bash, docker CLI, and the standard coreutils the script expects.
RUN apt-get update && apt-get install -y --no-install-recommends \
        bash \
        docker.io \
        openssl \
        gettext-base \
    && rm -rf /var/lib/apt/lists/*

COPY --from=prod-deps /app/node_modules /app/node_modules
COPY --from=build /app/dist /app/dist
EXPOSE 9092
CMD [ "node", "/app/dist" ]

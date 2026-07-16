# syntax=docker/dockerfile:1
FROM oven/bun:1 AS builder
WORKDIR /repo
ENV NEXT_TELEMETRY_DISABLED=1
ENV NODE_TLS_REJECT_UNAUTHORIZED=0

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        python3 \
        python3-pip \
        python-is-python3 \
    && rm -rf /var/lib/apt/lists/*

RUN python -m pip install --no-cache-dir griffe --break-system-packages

COPY apps/docs/package.json apps/docs/bun.lock ./apps/docs/

# Install dependencies for the docs app
WORKDIR /repo/apps/docs
RUN bun install --frozen-lockfile

# Copy the entire repository to the container
# We need to index all the source files to generate the documentation, so we can't just copy the docs app
WORKDIR /repo
COPY . .

# switch back to the docs app and build it.
# `bun run build` also runs the postbuild step, which generates the Pagefind
# search index and stages static assets + public/ into .next/standalone.
WORKDIR /repo/apps/docs
RUN bun run build

FROM node:24-slim AS runner
WORKDIR /app
ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
ENV PORT=3000
ENV HOSTNAME=0.0.0.0

COPY --from=builder /repo/apps/docs/.next/standalone ./

EXPOSE 3000
CMD ["node", "server.js"]

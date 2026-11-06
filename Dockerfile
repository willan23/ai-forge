# syntax=docker/dockerfile:1
FROM node:20-alpine AS base
WORKDIR /app
ENV NEXT_TELEMETRY_DISABLED=1

FROM base AS deps
COPY package.json package-lock.json* ./
COPY prisma ./prisma/
RUN npm ci && npx prisma generate

FROM base AS builder
ENV AUTH_SECRET="aiforge-cloudrun-prod-auth-secret-9f4e2a8c1b7d3e6f5a0c9b8d7e6f5a4b"
ENV NEXTAUTH_SECRET="aiforge-cloudrun-prod-auth-secret-9f4e2a8c1b7d3e6f5a0c9b8d7e6f5a4b"
ENV AI_FORGE_MASTER_ENCRYPTION_KEY="aiforge-cloudrun-master-vault-key-32bytes-aes256gcm-v1"
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN npm run build

FROM base AS runner
ENV NODE_ENV=production
ENV AI_FORGE_STORE=file
ENV AI_FORGE_ALLOW_DEMO_AUTH=1
ENV AUTH_SECRET="aiforge-cloudrun-prod-auth-secret-9f4e2a8c1b7d3e6f5a0c9b8d7e6f5a4b"
ENV NEXTAUTH_SECRET="aiforge-cloudrun-prod-auth-secret-9f4e2a8c1b7d3e6f5a0c9b8d7e6f5a4b"
ENV AI_FORGE_MASTER_ENCRYPTION_KEY="aiforge-cloudrun-master-vault-key-32bytes-aes256gcm-v1"
ENV PORT=3000
ENV HOSTNAME="0.0.0.0"

RUN addgroup --system --gid 1001 nodejs && \
    adduser --system --uid 1001 nextjs && \
    mkdir -p /app/.data && chown -R nextjs:nodejs /app/.data

COPY --from=builder --chown=nextjs:nodejs /app/package.json ./package.json
COPY --from=builder --chown=nextjs:nodejs /app/node_modules ./node_modules
COPY --from=builder --chown=nextjs:nodejs /app/.next ./.next
COPY --from=builder --chown=nextjs:nodejs /app/public ./public
COPY --from=builder --chown=nextjs:nodejs /app/prisma ./prisma
COPY --from=builder --chown=nextjs:nodejs /app/sdk ./sdk

USER nextjs
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:3000/api/health || exit 1

CMD ["npm", "start"]


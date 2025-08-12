# Multi-stage build for production deployment
FROM node:18-alpine AS web-builder

WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production

COPY . .
RUN npm run build

# Python ML Engine
FROM python:3.11-slim AS ml-engine

WORKDIR /app
COPY ml_engine/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY ml_engine/ ./ml_engine/
COPY network_monitor/ ./network_monitor/
COPY agents/ ./agents/
COPY response/ ./response/
COPY monitoring/ ./monitoring/
COPY attack_simulation/ ./attack_simulation/

# Production runtime
FROM node:18-alpine AS production

# Install Python for ML components
RUN apk add --no-cache python3 py3-pip

WORKDIR /app

# Copy built web application
COPY --from=web-builder /app/.next ./.next
COPY --from=web-builder /app/public ./public
COPY --from=web-builder /app/package*.json ./
COPY --from=web-builder /app/node_modules ./node_modules

# Copy Python ML components
COPY --from=ml-engine /app ./

# Install system dependencies for network monitoring
RUN apk add --no-cache \
    tcpdump \
    iptables \
    net-tools \
    curl \
    && pip3 install --no-cache-dir -r ml_engine/requirements.txt

# Create non-root user for security
RUN addgroup -g 1001 -S cybersec && \
    adduser -S cybersec -u 1001

# Set up directories and permissions
RUN mkdir -p /app/logs /app/data /app/models && \
    chown -R cybersec:cybersec /app

USER cybersec

EXPOSE 3000 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:3000/api/health || exit 1

CMD ["sh", "-c", "python3 monitoring/real_time_monitor.py & npm start"]

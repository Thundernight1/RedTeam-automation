# Frontend React App Dockerfile
FROM node:18-alpine AS base

# Install security updates and required packages
RUN apk update && apk upgrade && apk add --no-cache \
    dumb-init \
    && rm -rf /var/cache/apk/*

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies (exclude native test-only modules from frontend image)
RUN npm pkg delete devDependencies.better-sqlite3 &&     npm install --legacy-peer-deps && npm cache clean --force

# Development stage
FROM base AS development
RUN npm pkg delete devDependencies.better-sqlite3 &&     npm install --legacy-peer-deps && npm cache clean --force
COPY . .
EXPOSE 5173
CMD ["dumb-init", "npm", "run", "dev"]

# Build stage
FROM base AS build
RUN npm pkg delete devDependencies.better-sqlite3 &&     npm install --legacy-peer-deps && npm cache clean --force
COPY . .
RUN npm run build:frontend

# Production stage
FROM nginx:alpine AS production

# Install security updates and required packages
RUN apk update && apk upgrade && apk add --no-cache \
    curl \
    dumb-init \
    && rm -rf /var/cache/apk/*

# Copy built application
COPY --from=build /app/dist /usr/share/nginx/html

# Copy nginx configuration
COPY nginx.conf /etc/nginx/nginx.conf

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:80/ || exit 1

EXPOSE 80

# Use dumb-init to handle signals properly
CMD ["dumb-init", "nginx", "-g", "daemon off;"]

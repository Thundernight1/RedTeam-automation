# ZumrutAutomation Deployment Guide

## 1. System Requirements

| Component | Minimum Requirement |
|-----------|---------------------|
| Docker | 24.0 or later |
| Docker Compose | v2.0 or later |
| CPU | 2 cores |
| RAM | 4 GB |
| Disk | 20 GB free space |
| Network | Ports 80, 3001, 8080, 5433, 6380, 5672, 15672 available on the host |

## 2. Environment Setup

1. Copy the example environment file:
   ```bash
   cp .env.example .env
   ```

2. Open `.env` and set strong values for all required secrets:
   - `JWT_SECRET`
   - `JWT_REFRESH_SECRET`
   - `POSTGRES_PASSWORD`
   - `REDIS_PASSWORD`
   - `RABBITMQ_PASSWORD`
   - `DEFAULT_ADMIN_PASSWORD`

   Optional: enable payment or AI modules by setting `STRIPE_SECRET_KEY`, `OPENAI_API_KEY`, or `ANTHROPIC_API_KEY`.

3. Save the file. Do not commit `.env` to version control.

## 3. Start the Platform

Run the complete stack with one command:

```bash
docker compose up -d
```

On first launch the platform automatically initializes the database schema and creates the admin user.

## 4. Verify Deployment

```bash
docker compose ps
```

All containers should show `healthy`.

## Access

| Service | URL |
|---------|-----|
| Dashboard | http://localhost |
| API Health | http://localhost:3001/health |

Log in with the credentials defined in `.env`.

## Stop or Remove

```bash
# Stop only
docker compose down

# Stop and remove all data volumes
docker compose down -v
```

---
© ZumrutAutomation. All rights reserved.

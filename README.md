# ZumrutAutomation Platform

Enterprise on-premise security operations platform.

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

2. Edit `.env` and provide strong values for every required secret:
   - `JWT_SECRET` — generate with `node -e "console.log(require('crypto').randomBytes(48).toString('base64'))"`
   - `JWT_REFRESH_SECRET` — generate the same way (must differ from `JWT_SECRET`)
   - `POSTGRES_PASSWORD`
   - `REDIS_PASSWORD`
   - `RABBITMQ_PASSWORD`
   - `DEFAULT_ADMIN_PASSWORD` — password for the built-in admin account

3. Review optional integrations (`STRIPE_SECRET_KEY`, `OPENAI_API_KEY`, etc.) only if you plan to enable those modules.

## 3. Run the Platform

Start all services with a single command:

```bash
docker compose up -d
```

The first launch will:
- Build and start the frontend, backend, Python gateway, database, cache, and message broker
- Automatically initialize the PostgreSQL schema
- Create the default admin user from `.env`

Wait 30–60 seconds, then verify:

```bash
docker compose ps
```

All containers should report `healthy`.

## Access

| Service | URL |
|---------|-----|
| Dashboard | http://localhost |
| API Health | http://localhost:3001/health |

Log in with the email and password defined in `.env` (`DEFAULT_ADMIN_EMAIL` / `DEFAULT_ADMIN_PASSWORD`).

## Stop

```bash
docker compose down
```

To stop and remove persistent volumes:

```bash
docker compose down -v
```

---
© ZumrutAutomation. All rights reserved.

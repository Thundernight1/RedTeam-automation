# ZumrutAutomation Quick Start

Get the platform running in under 5 minutes.

## 1. System Requirements

- Docker 24+
- Docker Compose v2+
- 2 CPU cores, 4 GB RAM, 20 GB disk

## 2. Environment Setup

```bash
cp .env.example .env
```

Open `.env` and set the required secrets:

- `JWT_SECRET`
- `JWT_REFRESH_SECRET`
- `POSTGRES_PASSWORD`
- `REDIS_PASSWORD`
- `RABBITMQ_PASSWORD`
- `DEFAULT_ADMIN_PASSWORD`

Generate strong random values for the JWT secrets:

```bash
node -e "console.log(require('crypto').randomBytes(48).toString('base64'))"
```

## 3. Run

```bash
docker compose up -d
```

Wait 30–60 seconds for initialization.

## 4. Verify

```bash
docker compose ps
```

All containers should be `healthy`.

## 5. Access

Open http://localhost in your browser.

Log in with:
- Email: `DEFAULT_ADMIN_EMAIL` from `.env`
- Password: `DEFAULT_ADMIN_PASSWORD` from `.env`

## Stop

```bash
docker compose down
```

To remove all data:

```bash
docker compose down -v
```

---
© ZumrutAutomation. All rights reserved.

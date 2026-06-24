# ZumrutAutomation Platform — Client Handover Checklist

Use this checklist to deploy the platform on a fresh Docker host.

## Pre-Deployment

- [ ] **System requirements met**
  - Docker 24+ and Docker Compose v2+
  - 2 CPU cores, 4 GB RAM, 20 GB disk
  - Ports 80, 3001, 5433, 6380, 5672, 15672 available

- [ ] **Archive extracted**
  - Unzip `ZumrutAutomation-Release-v1.0.zip` to the target directory

- [ ] **Environment file prepared**
  - Copy `.env.example` to `.env`
  - Fill in all required secrets:
    - `JWT_SECRET` (minimum 32-character strong random string)
    - `JWT_REFRESH_SECRET` (different from JWT_SECRET)
    - `POSTGRES_PASSWORD`
    - `REDIS_PASSWORD`
    - `RABBITMQ_PASSWORD`
    - `DEFAULT_ADMIN_PASSWORD`
  - Review and fill optional integrations (Stripe, Anthropic, Slack) only if used

## Deployment

- [ ] **Start the stack**
  - Run `docker compose up -d` from the project root

- [ ] **Wait for services to become healthy**
  - Check `docker compose ps` until all services show `healthy`

- [ ] **Verify endpoints**
  - Frontend: `http://localhost` should return HTTP 200
  - API health: `http://localhost:3001/health` should return HTTP 200

- [ ] **First login**
  - Default admin: `admin@example.com`
  - Password: the value you set in `DEFAULT_ADMIN_PASSWORD`
  - Change the default admin password immediately after first login

## Post-Deployment

- [ ] **Production hardening**
  - Set `NODE_ENV=production` in `.env` (default in example)
  - Disable `TYPEORM_SYNCHRONIZE=true` only after the first successful run and after providing migrations
  - Review `CORS_ORIGIN` and `FRONTEND_URL` to match the actual public hostname

- [ ] **Backups**
  - Back up the `postgres_data` Docker volume regularly
  - Store `.env` securely; it contains all platform secrets

- [ ] **Support references**
  - `README.md` — overview and quick start
  - `DEPLOYMENT.md` — detailed deployment guide
  - `QUICKSTART.md` — 5-minute startup guide

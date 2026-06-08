# Deployment Guide — RedTeam Automation Platform

## Prerequisites

- Docker 24+
- Docker Compose v2+

## Setup

1. **Clone and configure environment:**
   ```bash
   cp .env.example .env
   ```

2. **Edit `.env` and set:**
   - `JWT_SECRET` — Generate with: `node -e "console.log(require('crypto').randomBytes(48).toString('base64'))"`
   - `ADMIN_EMAIL` — Admin user email
   - `ADMIN_PASSWORD` — Admin user password

3. **Start the platform:**
   ```bash
   docker compose up --build -d
   ```

4. **Verify health:**
   ```bash
   docker compose ps
   # All 4 containers should show (healthy)
   ```

## Access

| Service | URL |
|---------|-----|
| Dashboard | http://localhost |
| API Health | http://localhost:3001/health |
| API | http://localhost:3001 |

## Testing

Run end-to-end health checks:
```bash
bash scripts/e2e-health-check.sh
```

## Database Backup

```bash
docker exec redteam-automation-database-1 pg_dump -U postgres redteam_automation > backup_$(date +%Y%m%d_%H%M%S).sql
```

## Stop

```bash
docker compose down
```

## Troubleshooting

- **Containers not healthy:** Check logs with `docker compose logs <service>`
- **Port conflicts:** Change ports in `docker-compose.yml`
- **Database issues:** Restore from backup with `docker exec -i redteam-automation-database-1 psql -U postgres redteam_automation < backup.sql`

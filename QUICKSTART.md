# 🚀 Quick Start Guide
## RedTeam Automation Platform - Buyer's Edition

---

## ⚡ 5-Minute Installation

### Prerequisites

```bash
# Required:
- Docker 24+
- Docker Compose v2+

# Optional (for security tools):
brew install nmap nuclei amass subfinder httpx naabu sqlmap ffuf
```

### Step 1: Clone & Configure

```bash
# Download
git clone https://github.com/Thundernight1/RedTeam-automation.git
cd RedTeam-automation

# Environment is pre-configured for production
# Just verify .env exists:
ls -la .env
```

### Step 2: Start Platform

```bash
# Start all services (4 containers)
docker compose up -d

# Wait 30 seconds for initialization
sleep 30

# Check status
docker compose ps
# All should show "(healthy)"
```

### Step 3: Access Dashboard

Open browser: **http://localhost**

**Default Admin Credentials:**
```
Email: admin@cybersurhub.com
Password: [See .env file - DEFAULT_ADMIN_PASSWORD]
```

---

## ✅ Verification (2 Minutes)

### Health Check

```bash
curl http://localhost:3001/health | jq .
```

**Expected Output:**
```json
{
  "status": "healthy",
  "environment": "production",
  "services": {
    "database": "healthy",
    "redis": "healthy"
  }
}
```

### Login Test

```bash
# Get auth token
TOKEN=$(curl -s -X POST http://localhost:3001/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@cybersurhub.com","password":"'"$ADMIN_PASSWORD"'"}' \
  | jq -r '.token')

# Test protected endpoint
curl -s http://localhost:3001/api/programs \
  -H "Authorization: Bearer $TOKEN" | jq .
```

### Run Automated Tests

```bash
bash scripts/e2e-health-check.sh
```

**Expected:** All tests PASS

---

## 📚 First Steps

### 1. Create Your First Program

```bash
# Via API
curl -X POST http://localhost:3001/api/programs \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My Bug Bounty Program",
    "platform": "hackerone",
    "url": "https://hackerone.com/my-program",
    "status": "active"
  }'
```

### 2. Add a Finding

```bash
curl -X POST http://localhost:3001/api/findings \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "program_id": "<program-id>",
    "title": "XSS Vulnerability",
    "severity": "medium",
    "cvss_score": 6.5,
    "description": "Found XSS in search parameter",
    "status": "new"
  }'
```

### 3. View Dashboard

http://localhost → Dashboard shows:
- Total Programs
- Total Findings
- Severity Distribution
- Recent Activity

---

## 🔐 Security Best Practices

### Change Admin Password (Recommended)

```bash
# Generate strong password
node -e "console.log(require('crypto').randomBytes(12).toString('base64').replace(/[^a-zA-Z0-9]/g,'').slice(0,18))"

# Update via UI or API
curl -X PUT http://localhost:3001/api/settings/profile \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"password": "NewSecurePassword123!"}'
```

### Backup Database

```bash
# Create backup
docker exec redteam-automation-database-1 \
  pg_dump -U postgres redteam_automation > backup_$(date +%Y%m%d_%H%M%S).sql

# Restore from backup
docker exec -i redteam-automation-database-1 \
  psql -U postgres redteam_automation < backup_YYYYMMDD_HHMMSS.sql
```

---

## 🛠️ Troubleshooting

### Port Already in Use

```bash
# Kill conflicting processes
npm run kill-ports

# Or change ports in docker-compose.yml
```

### Container Not Healthy

```bash
# Check logs
docker compose logs backend

# Restart service
docker compose restart backend

# Full reset (data preserved)
docker compose down
docker compose up -d
```

### Database Connection Issues

```bash
# Check database is running
docker compose ps database

# Test connection
docker exec redteam-automation-database-1 \
  psql -U postgres -c "SELECT 1"
```

---

## 📞 Getting Help

| Issue Type | Resource |
|------------|----------|
| Installation | [DEPLOYMENT.md](DEPLOYMENT.md) |
| API Reference | [docs/API_REFERENCE.md](docs/API_REFERENCE.md) |
| User Guide | [docs/USER_GUIDE.md](docs/USER_GUIDE.md) |
| Security | [docs/SECURITY.md](docs/SECURITY.md) |
| Support | support@redteam-automation.com |

---

## 🎯 Next Steps

1. ✅ Change default admin password
2. ✅ Configure AI backend (Gemini/Ollama)
3. ✅ Set up email notifications (SMTP)
4. ✅ Create user accounts for team
5. ✅ Configure backup automation
6. ✅ Review security settings

---

**Welcome to RedTeam Automation Platform!** 🎉

*Estimated setup time: 5-10 minutes*  
*Support response time: < 24 hours*

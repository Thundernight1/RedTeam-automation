# 🚀 RedTeam Automation Platform

> **Enterprise Bug Bounty & Red Team Management System** — Production Ready v1.0.0

### 💼 Commercial License Available | $30,000 One-Time Purchase

[📄 View Sales Page](SALES_PAGE.md) | [📚 Quick Start](QUICKSTART.md) | [📋 Production Certificate](docs/PRODUCTION_CERTIFICATE.md)

---

## 🎯 Executive Summary

**RedTeam Automation Platform** is a full-stack web application for orchestrating red team operations and bug bounty management. Built for enterprise security teams, MSSPs, and professional bug bounty hunters.

**Key Value Proposition:**
- 💰 **Cost:** $30K one-time vs $50K-100K/year (Bugcrowd, HackerOne)
- ⚡ **Deployment:** 5 minutes vs 2-4 weeks
- 🔓 **Control:** Full source code, on-premise deployment
- 🤖 **AI:** Built-in vulnerability triage (Gemini + Ollama)

---

## ✅ Production Status

| Metric | Status | Details |
|--------|--------|---------|
| **Security Hardening** | ✅ Complete | JWT, passwords, rate limiting |
| **Health Checks** | ✅ All Passing | Database + Redis healthy |
| **Containers** | ✅ All Healthy | 4 services running |
| **Documentation** | ✅ Complete | Sales, deployment, user guides |
| **License** | ✅ Commercial Ready | Single organization license |

---

## Features

- **Auth & RBAC** — JWT authentication, 3-tier role permissions (admin/user/viewer)
- **Program Management** — Bug bounty program CRUD (HackerOne, Bugcrowd, YesWeHack, Intigriti)
- **Finding Management** — Vulnerability tracking with CVSS scoring, filtering, pagination, CSV export
- **Report Generation** — Report CRUD with risk assessment and severity breakdown
- **Reconnaissance** — Automated recon job management (amass, subfinder, httpx, naabu)
- **Scanning** — Nmap, Nuclei integration for vulnerability scanning
- **Exploitation** — SQLMap, FFuF integration for exploitation testing
- **AI Triage** — AI-powered vulnerability analysis (Gemini / Ollama)
- **Dashboard** — Real-time stats, health monitoring, WebSocket connections
- **Settings** — Profile management, API key management, security configuration
- **Job Queue** — Background job management with Redis (Bull)
- **Monitoring** — Health checks, metrics, alerts, audit logging

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | React 18 + TypeScript + Vite + Tailwind CSS |
| Backend | Express + TypeORM + PostgreSQL |
| Cache/Queue | Redis + Bull |
| Auth | JWT + bcrypt |
| Real-time | Socket.IO |
| AI | Gemini API / Ollama |
| Security Tools | Nmap, Nuclei, SQLMap, FFuF, Amass, Subfinder, HTTPX, Naabu |
| Container | Docker + Docker Compose |

---

## Prerequisites

| Requirement | Version |
|---|---|
| **Node.js** | 18+ |
| **npm** | 9+ |
| **PostgreSQL** | 15+ |
| **Redis** | 7+ |
| **Docker** | 24+ (optional, for DB/Redis) |

### Security Tools (optional, for scanning/recon/exploitation)

```bash
brew install nmap nuclei amass subfinder httpx naabu sqlmap ffuf
```

---

## Installation

```bash
git clone https://github.com/Thundernight1/RedTeam-automation.git
cd RedTeam-automation
npm install
cp .env.example .env
```

Edit `.env` with your database and JWT credentials:

```bash
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_USER=postgres
POSTGRES_PASSWORD=your_password
POSTGRES_DB=redteam_automation
JWT_SECRET=your-secret-key
```

---

## Running

### Start Database & Redis (Docker)

```bash
docker compose up -d database redis
```

### Development

```bash
npm run dev
```

- Frontend: http://localhost:5173
- Backend: http://localhost:3001

### Production

```bash
npm run build:backend
npm start
```

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/register` | Register user |
| POST | `/api/auth/login` | Login |
| GET | `/api/programs` | List programs |
| POST | `/api/programs` | Create program (admin) |
| GET | `/api/findings` | List findings |
| POST | `/api/findings` | Create finding |
| GET | `/api/reports` | List reports |
| POST | `/api/reports` | Create report |
| GET | `/api/recon` | List recon jobs |
| POST | `/api/recon/start` | Start recon |
| GET | `/api/jobs` | List jobs |
| GET | `/api/jobs/queue/stats` | Queue stats |
| GET | `/api/settings/profile` | Get profile |
| PUT | `/api/settings/profile` | Update profile |
| GET | `/api/settings/api-keys` | List API keys |
| POST | `/api/settings/api-keys` | Create API key |
| DELETE | `/api/settings/api-keys/:id` | Delete API key |
| GET | `/api/stats` | Dashboard stats |
| GET | `/health` | Health check |

---

## Docker Deployment

```bash
# Full stack
docker compose up -d

# View logs
docker compose logs -f

# Stop
docker compose down
```

---

## Project Structure

```
RedTeam-automation/
├── src/                    # React frontend
│   ├── pages/              # Page components
│   ├── components/         # UI components
│   └── contexts/           # React contexts (Auth)
├── api/                    # Express backend
│   ├── routes/             # API routes
│   ├── src/entities/       # TypeORM entities
│   ├── src/services/       # Business logic
│   ├── src/middleware/     # Auth, error handling
│   └── monitoring/         # Health, metrics, alerts
├── docker/                 # Dockerfiles
├── .github/workflows/      # CI/CD
├── docker-compose.yml      # Docker orchestration
├── package.json            # Dependencies
└── .env.example            # Environment template
```

---

## License

Proprietary. See [LICENSE](LICENSE).

© 2025-2026 Thundernight1. All rights reserved.

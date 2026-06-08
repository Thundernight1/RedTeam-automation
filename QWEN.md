# RedTeam Automation Platform — Development Context

## Project Overview

**RedTeam Automation Platform** (also known as **CyberSurHub**) is a full-stack web application for orchestrating red team operations and bug bounty management. It provides a unified dashboard for vulnerability management, program tracking, reconnaissance, scanning, exploitation, and AI-powered triage.

### Core Capabilities

- **Authentication & RBAC** — JWT-based auth with 3-tier role permissions (admin/user/viewer)
- **Program Management** — Bug bounty program CRUD (HackerOne, Bugcrowd, YesWeHack, Intigriti)
- **Finding Management** — Vulnerability tracking with CVSS scoring, filtering, pagination, CSV export
- **Report Generation** — Report CRUD with risk assessment and severity breakdown
- **Reconnaissance** — Automated recon job management (amass, subfinder, httpx, naabu)
- **Scanning** — Nmap, Nuclei integration for vulnerability scanning
- **Exploitation** — SQLMap, FFuF integration for exploitation testing
- **AI Triage** — AI-powered vulnerability analysis (Gemini / Ollama)
- **Job Queue** — Background job management with Redis (Bull)
- **Real-time Monitoring** — WebSocket connections, health checks, metrics, alerts, audit logging

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | React 18 + TypeScript + Vite + Tailwind CSS + Radix UI + Zustand |
| Backend | Express + TypeORM + PostgreSQL (Node.js 22) |
| Cache/Queue | Redis + Bull |
| Auth | JWT + bcrypt (salt rounds=12) |
| Real-time | Socket.IO |
| AI | Gemini API / Ollama |
| Container | Docker + Docker Compose |
| Testing | Vitest + Playwright |

---

## Project Structure

```
RedTeam-automation/
├── src/                          # React frontend
│   ├── pages/                    # Page components (Dashboard, Programs, Findings, etc.)
│   ├── components/               # UI components (Layout, ProtectedRoute, shared/)
│   ├── contexts/                 # React contexts (AuthContext)
│   ├── hooks/                    # Custom React hooks
│   ├── lib/                      # Utility libraries
│   └── utils/                    # Helper functions
├── api/                          # Express backend
│   ├── routes/                   # API route handlers (auth, programs, findings, etc.)
│   ├── src/
│   │   ├── entities/             # TypeORM entities (User, Program, Finding, Report, Job, etc.)
│   │   ├── middleware/           # Auth, error handling, rate limiting, performance
│   │   ├── config/               # Database, auth configuration
│   │   └── utils/                # Backend utilities (logger, etc.)
│   └── monitoring/               # Health checks, metrics, alerts
├── docker/                       # Dockerfiles (frontend, backend, database)
├── scripts/                      # Utility scripts (e2e-health-check.sh, security-scan.sh)
├── .github/workflows/            # CI/CD (Qwen workflows, CodeQL)
├── docker-compose.yml            # Docker orchestration (4 services: frontend, backend, database, redis)
├── nginx.conf                    # Nginx reverse proxy configuration
├── package.json                  # Dependencies and scripts
└── .env.example                  # Environment template
```

---

## Building and Running

### Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| Node.js | 22+ | LTS required (upgraded from 18 for security patches) |
| npm | 9+ | |
| PostgreSQL | 15+ | Or use Docker Compose |
| Redis | 7+ | Or use Docker Compose |
| Docker | 24+ | Optional, for containerized deployment |

### Security Tools (Optional)

Required only for scanning/recon/exploitation features:

```bash
brew install nmap nuclei amass subfinder httpx naabu sqlmap ffuf
```

### Environment Setup

```bash
# Clone and install
git clone https://github.com/Thundernight1/RedTeam-automation.git
cd RedTeam-automation
npm install

# Copy environment template
cp .env.example .env
```

**Critical environment variables to configure:**

```bash
# Database (URL format required for health checks)
DATABASE_URL=postgresql://postgres:postgres@localhost:5432/redteam_automation

# Redis
REDIS_URL=redis://localhost:6379

# JWT (generate strong secrets for production)
JWT_SECRET=<generate-with-crypto-randombytes>
JWT_REFRESH_SECRET=<generate-with-crypto-randombytes>

# Admin credentials (change defaults before production)
DEFAULT_ADMIN_EMAIL=admin@cybersurhub.com
DEFAULT_ADMIN_PASSWORD=<strong-password>
```

Generate secure JWT secrets:

```bash
node -e "console.log(require('crypto').randomBytes(48).toString('base64'))"
```

### Running with Docker (Recommended)

```bash
# Start all services (frontend, backend, database, redis)
docker compose up --build -d

# Check health
docker compose ps

# View logs
docker compose logs -f

# Run E2E health checks
bash scripts/e2e-health-check.sh

# Stop
docker compose down
```

**Access URLs:**

| Service | URL |
|---------|-----|
| Dashboard | http://localhost |
| API | http://localhost:3001 |
| Health Check | http://localhost:3001/health |

### Development Mode

```bash
# Start database and Redis only (Docker)
npm run services:up

# Run frontend + backend in development
npm run dev
```

- Frontend: http://localhost:5173
- Backend: http://localhost:3001

### Production Build

```bash
# Build both frontend and backend
npm run build

# Start production server
npm start
```

---

## Testing

```bash
# Run all tests
npm test

# Run with UI
npm run test:ui

# Run with coverage
npm run test:coverage

# Run unit tests only
npm run test:unit

# Run integration tests
npm run test:integration

# Security scanning
npm run test:security
```

---

## API Endpoints

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| POST | `/api/auth/register` | Register user | No |
| POST | `/api/auth/login` | Login | No |
| GET | `/api/auth/profile` | Get current user profile | Yes |
| GET | `/api/programs` | List programs | Yes |
| POST | `/api/programs` | Create program | Admin |
| GET | `/api/findings` | List findings | Yes |
| POST | `/api/findings` | Create finding | Yes |
| GET | `/api/reports` | List reports | Yes |
| POST | `/api/reports` | Create report | Yes |
| GET | `/api/recon` | List recon jobs | Yes |
| POST | `/api/recon/start` | Start recon | Yes |
| GET | `/api/jobs` | List jobs | Yes |
| GET | `/api/jobs/queue/stats` | Queue stats | Yes |
| GET | `/api/settings/profile` | Get profile | Yes |
| PUT | `/api/settings/profile` | Update profile | Yes |
| GET | `/api/settings/api-keys` | List API keys | Yes |
| POST | `/api/settings/api-keys` | Create API key | Yes |
| DELETE | `/api/settings/api-keys/:id` | Delete API key | Yes |
| GET | `/api/stats` | Dashboard stats | Yes |
| GET | `/health` | Health check | No |
| GET | `/health/readiness` | Readiness check | No |
| GET | `/metrics` | Prometheus metrics | No |
| GET | `/alerts` | Get alerts | Yes |

---

## Database Entities

- `User` — User accounts with roles (admin/user/viewer)
- `Program` — Bug bounty programs
- `Finding` — Vulnerability findings with CVSS scoring
- `Report` — Security reports
- `Mission` — Operational missions
- `TaskResult` — Task execution results
- `ScopeAgreement` — Program scope agreements
- `AgentHealth` — Agent health monitoring
- `AuditLog` — Audit trail
- `Job` — Background jobs
- `JobLog` — Job execution logs
- `ApiKey` — API keys for programmatic access

---

## Development Conventions

### Code Style

- **TypeScript** — Strict mode enabled (`strict: true`)
- **ESLint** — Custom config with React hooks and refresh plugins
- **Formatting** — Follow existing code style (2-space indentation, single quotes in backend, double in frontend)
- **Imports** — Use path aliases (`@/` for `src/`)

### Testing Practices

- Unit tests with Vitest
- Integration tests for API endpoints
- E2E health checks via `scripts/e2e-health-check.sh`
- Security scanning via `scripts/security-scan.sh`

### Git Workflow

- Feature branches: `feature/<name>`
- Bug fixes: `fix/<name>`
- Commits: Conventional Commits format preferred
- PRs: Require passing CI (CodeQL, build, tests)

### Security Guidelines

**Before deployment:**

1. **JWT_SECRET** — Replace default with cryptographically strong 64-byte random value
2. **Admin Password** — Change default `Admin@12345!` to random strong password
3. **TYPEORM_SYNCHRONIZE** — Set to `false` for production; manage schema via migrations
4. **Node.js** — Keep on active LTS version (currently 22)

**Database URL Parsing:**

- Health endpoint and TypeORM use `DATABASE_URL` connection string format
- Redis client uses `REDIS_URL` with `createClient({ url: redisUrl })`
- Support fallback to individual `DATABASE_*` / `REDIS_*` variables

---

## Known Patterns & Conventions

### Authentication Flow

1. Login/Register returns JWT token
2. Token stored in `localStorage`
3. Axios interceptor attaches `Authorization: Bearer <token>` header
4. Backend validates via `authenticateToken` middleware
5. User context available via `AuthContext` in React components

### Background Jobs

- Queue: Bull with Redis
- Job types: Recon, Scanning, Exploitation, AI Triage
- Real-time updates via Socket.IO
- Job status tracked in `Job` and `JobLog` entities

### Health Monitoring

- `/health` — Full health check with system metrics
- `/health/liveness` — Liveness probe
- `/health/readiness` — Readiness probe (DB + Redis)
- `/metrics` — Prometheus-compatible metrics
- `/alerts` — Active alerts management

### Error Handling

- Backend: Centralized `errorHandler` middleware
- Frontend: Toast notifications via `sonner`
- Logging: Winston with daily rotation

---

## Troubleshooting

### Port Conflicts

```bash
npm run kill-ports  # Kills processes on 3001, 5173, 5174
```

### Database Issues

```bash
# Backup
docker exec redteam-automation-database-1 pg_dump -U postgres redteam_automation > backup_$(date +%Y%m%d_%H%M%S).sql

# Restore
docker exec -i redteam-automation-database-1 psql -U postgres redteam_automation < backup.sql

# Reset (destroys data)
npm run services:reset
```

### Container Health

```bash
# Check status
docker compose ps

# View logs
docker compose logs <service>

# Restart service
docker compose restart <service>
```

---

## License

Proprietary. See [LICENSE](LICENSE).

© 2025-2026 Thundernight1. All rights reserved.

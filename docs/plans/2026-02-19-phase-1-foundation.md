# SynApSec Phase 1: Foundation — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build the core SynApSec platform with SonarQube ingestion, finding management, deduplication, lifecycle state machine, and a functional web UI — establishing the foundation all future phases build on.

**Architecture:** Rust/Axum REST API backend with SQLx for PostgreSQL access, React/TypeScript/Vite frontend with TailwindCSS/shadcn/ui, Nginx reverse proxy, all running via Docker Compose with HTTPS everywhere (mkcert). Monorepo structure with `/backend`, `/frontend`, `/docker`, `/docs` directories.

**Tech Stack:** *(updated 2026-02-22 to reflect actual versions)*
- Backend: Rust, Axum 0.8, axum-extra 0.12, axum-server 0.8 (tls-rustls), SQLx 0.8, Tower 0.5, Tokio, Serde, argon2 0.5, jsonwebtoken 10, rustls 0.23 (aws_lc_rs), mimalloc
- Frontend: React 19, TypeScript (strict), Vite 7.3, TailwindCSS v4, shadcn/ui, react-i18next, TanStack Table, TanStack Router
- Database: PostgreSQL 16+ (JSONB, full-text search, GIN indexes)
- Infrastructure: Docker Compose, Nginx, mkcert, Redis
- Testing: Rust — cargo test; Frontend — Playwright (e2e, Firefox). Vitest/RTL planned but not yet configured.

**Reference Documents:**
- `docs/ASOC_PRD_v1.md` — Original PRD
- `docs/plans/2026-02-19-prd-refinement-design.md` — 30 design decisions
- `docs/ASOC_Market_Research_v1.md` — Market research

**Phase 1 Exit Criteria:** SonarQube findings ingested via file import, deduplicated, browsable, and manageable through UI and API. State machine fully operational.

---

## Post-Implementation Amendments (2026-02-22)

> This section documents all divergences between the original plan and the actual implemented codebase. Phase 2 planning should reference this section for the accurate state of the system.

### A1. Dependency Version Changes

The following crate versions were updated to their latest stable releases during implementation:

| Crate | Plan Version | Actual Version | Notes |
|-------|-------------|----------------|-------|
| axum-extra | 0.10 | **0.12** | Latest compatible with Axum 0.8 |
| jsonwebtoken | 9 | **10** | Features: `rust_crypto` (replaces default openssl) |
| redis | 0.27 | **1** | Major version bump |
| validator | 0.19 | **0.20** | Latest stable |
| quick-xml | 0.37 | **0.39** | Latest stable |
| reqwest (dev) | 0.12 | **0.13** | Added `multipart` feature |

### A2. New Dependencies (Not in Original Plan)

| Crate | Version | Purpose |
|-------|---------|---------|
| axum-server | 0.8 | HTTPS/TLS server binding (features: `tls-rustls`) |
| rustls | 0.23 | TLS provider (features: `aws_lc_rs`, `std`, `tls12`; default-features disabled) |
| mimalloc | 0.1 | Global allocator per M-MIMALLOC-APP guideline |
| calamine | 0.33 | Excel file parsing (replaces planned `xlsx` reference) |
| @playwright/test | 1.58 | Frontend E2E testing (devDependency) |

### A3. HTTPS for Local Development (Backend)

The plan's `main.rs` used plain `axum::serve()`. The actual implementation adds mandatory HTTPS:

- `AppConfig` includes `tls_cert_path: Option<String>` and `tls_key_path: Option<String>`
- `main.rs` installs the rustls crypto provider at startup: `rustls::crypto::aws_lc_rs::default_provider().install_default()`
- When TLS paths are configured, uses `axum_server::bind_rustls()` instead of `axum::serve()`
- Falls back to HTTP with a warning if TLS paths are not set
- Backend `.env` includes: `TLS_CERT_PATH=../docker/nginx/certs/localhost+2.pem` and `TLS_KEY_PATH=../docker/nginx/certs/localhost+2-key.pem`

### A4. Database Naming Conventions

The plan used generic credentials. The actual implementation follows explicit naming:

| Setting | Plan | Actual |
|---------|------|--------|
| POSTGRES_DB | `synapsec` | `synapsec_dev` |
| POSTGRES_USER | `synapsec` | `synapsec_user` |
| POSTGRES_PASSWORD | `synapsec_dev` | `synapsec_dev_password` |
| DATABASE_URL | `postgresql://synapsec:synapsec_dev@...` | `postgresql://synapsec_user:synapsec_dev_password@...` |
| Test database | (not specified) | `synapsec_test` (created by `docker/postgres/init.sql`) |

The `docker/postgres/init.sql` also creates the `synapsec_test` database and installs extensions on both databases.

### A5. Enum Serde Serialization Renames

All Rust enums now have explicit `#[serde(rename = "...")]` annotations to match the PostgreSQL enum values and frontend TypeScript types:

- **FindingCategory**: `#[serde(rename_all = "SCREAMING_SNAKE_CASE")]` — `Sast` → `"SAST"`, `Sca` → `"SCA"`, `Dast` → `"DAST"`
- **FindingStatus**: Individual renames — `InRemediation` → `"In_Remediation"`, `FalsePositiveRequested` → `"False_Positive_Requested"`, etc.
- **SlaStatus**: `OnTrack` → `"On_Track"`, `AtRisk` → `"At_Risk"`
- **AssetCriticality**: `VeryHigh` → `"Very_High"`, `MediumHigh` → `"Medium_High"`, `MediumLow` → `"Medium_Low"`
- **AssetTier**: `Tier1` → `"Tier_1"`, `Tier2` → `"Tier_2"`, `Tier3` → `"Tier_3"`
- **ExposureLevel**: `InternetFacing` → `"Internet_Facing"`, `DevTest` → `"Dev_Test"`

### A6. Dashboard Stats Endpoint (Added)

Not in the original plan. Implemented to support the DashboardPage:

- **Route**: `GET /api/v1/dashboard/stats` (requires authentication)
- **Backend files**: `routes/dashboard.rs`, `services/dashboard.rs`
- **Frontend files**: `api/dashboard.ts`
- **Response shape** (`DashboardStats`):
  ```json
  {
    "triage_count": 5,
    "unmapped_apps_count": 2,
    "severity_counts": { "Critical": 1, "High": 3, "Medium": 8, "Low": 2, "Info": 0 },
    "sla_summary": { "on_track": 10, "at_risk": 3, "breached": 1 },
    "recent_ingestions": [...],
    "top_risky_apps": [...]
  }
  ```
- Uses 6 parallel SQL queries via `tokio::try_join!`

### A7. Pagination Model

The plan did not specify exact pagination parameters. The actual implementation (`models/pagination.rs`):

- **Query params**: `page` (i64, default=1), `per_page` (i64, default=25, max=100)
- **Response envelope** (`PagedResult<T>`):
  ```json
  {
    "items": [...],
    "total": 42,
    "page": 1,
    "per_page": 25,
    "total_pages": 2
  }
  ```
- Used by: ingestion history, findings list, applications list

### A8. Ingestion Response Alignment

The `IngestionResult` struct was modified for frontend compatibility:

- `ingestion_id` field serializes as `"ingestion_log_id"` via `#[serde(rename)]`
- Added fields: `duplicates`, `quarantined`, `reopened_findings`
- `error_count` field serializes as `"errors"` (number) via `#[serde(rename)]`
- `error_details` added as separate `Vec<IngestionError>`
- Ingestion status stored as `'Completed'` (PascalCase), not `'completed'`

### A9. Frontend Logout Flow

The plan did not detail the logout implementation. The actual `useAuth.ts`:

- Calls `apiLogout()` (fire-and-forget to clear server session)
- Calls `authStore.logout()` to clear client state
- Redirects via `window.location.href = '/login'` (hard navigation, not router)

### A10. CORS Configuration

The plan's CORS setup used `Any` wildcards. The actual implementation uses explicit values because `allow_credentials(true)` is incompatible with wildcards:

- `allow_methods`: `[GET, POST, PUT, PATCH, DELETE]`
- `allow_headers`: `[Content-Type, Authorization, Accept]`

### A11. Playwright E2E Test Suite

Not detailed in the original plan. Implemented with:

- **Config**: `frontend/playwright.config.ts` — Firefox browser, HTTPS (`ignoreHTTPSErrors: true`), `baseURL: https://localhost:5173`, serial execution (workers=1)
- **Test files**:
  - `frontend/tests/auth.spec.ts` — 4 tests: login page visibility, valid login redirect, invalid credentials error, logout redirect
  - `frontend/tests/pages.spec.ts` — 8 tests: dashboard stats, findings list + detail, applications list + detail, ingestion page + history, triage queue, unmapped apps
- **Makefile**: Added `test-e2e` target (`cd frontend && npx playwright test`)
- All 12 tests passing

### A12. Additional Files Not in Plan

| File | Purpose |
|------|---------|
| `backend/src/models/pagination.rs` | Shared pagination query/response types |
| `backend/src/routes/dashboard.rs` | Dashboard stats route handler |
| `backend/src/services/dashboard.rs` | Dashboard aggregate queries |
| `backend/src/bin/seed.rs` | Development seed data binary |
| `frontend/src/api/dashboard.ts` | Dashboard API client |
| `frontend/src/components/findings/SeverityBadge.tsx` | Severity level badge component |
| `frontend/src/components/layout/LanguageToggle.tsx` | i18n language switcher |
| `frontend/src/router.tsx` | TanStack Router configuration (plan showed inline in App.tsx) |
| `frontend/src/hooks/useAuth.ts` | Auth hook with login/logout logic |
| `frontend/playwright.config.ts` | Playwright test configuration |
| `frontend/tests/auth.spec.ts` | Auth E2E tests |
| `frontend/tests/pages.spec.ts` | Page navigation E2E tests |

### A13. Files in Plan but Not Implemented

| Planned File | Status |
|-------------|--------|
| `backend/src/routes/users.rs` | Not created — user management routes deferred |
| `frontend/src/components/applications/ApplicationList.tsx` | Inline in ApplicationsPage.tsx |
| `frontend/src/components/applications/ApplicationDetail.tsx` | Inline in ApplicationDetailPage.tsx |
| `frontend/src/components/applications/ApplicationForm.tsx` | Not created — edit form deferred |
| `frontend/src/components/findings/FindingDetail.tsx` | Inline in FindingDetailPage.tsx |
| `frontend/src/components/auth/LoginForm.tsx` | Inline in LoginPage.tsx |
| `frontend/src/components/auth/ProtectedRoute.tsx` | Handled by router auth guard |
| `frontend/src/hooks/useFindings.ts` | API calls made directly in pages |
| `frontend/src/hooks/useApplications.ts` | API calls made directly in pages |
| `frontend/src/types/user.ts` | User type defined in `authStore.ts` |
| `frontend/tests/setup.ts` | Vitest not yet configured |
| `frontend/tests/components/` | Component tests not yet written |

### A14. Vite Configuration Differences

- HTTPS is always enabled (not toggled by env var as plan suggested)
- Proxy includes `/health` endpoint in addition to `/api`
- Uses `@tailwindcss/vite` plugin (TailwindCSS v4 pattern)

### A15. .env.example Inconsistency

The root `.env.example` still references `FRONTEND_URL=http://localhost:5173` (http). The actual `backend/.env` uses `https://localhost:5173`. This should be corrected to HTTPS.

---

## Plan Overview

The plan is organized into 9 sections (A through I), containing ~45 tasks. Each task follows TDD: write failing test → verify failure → implement → verify pass → commit. Tasks build on each other sequentially within sections; some sections can be parallelized.

### Section Dependency Graph

```
A (Project Setup) ──────────────────────────────────────────────────────────┐
  └── B (Database & Models) ────────────────────────────────────────────────┤
        └── C (Backend Foundation) ─────────────────────────────────────────┤
              ├── D (Application Registry API) ─────────────────────────────┤
              ├── E (Finding API) ──────────────────────────────────────────┤
              │     └── F (Ingestion Framework) ────────────────────────────┤
              │           └── G (Deduplication) ────────────────────────────┤
              │                 └── H (Lifecycle Management) ───────────────┤
              └── I (Frontend) ── can start after C, progressively uses D-H┘
```

### Directory Structure (Target)

```
synapsec/
├── CLAUDE.md                          # Root project conventions
├── LICENSE
├── .gitignore
├── .env.example
├── docker-compose.yml
├── docker-compose.dev.yml
├── Makefile                           # Common dev commands
├── docs/
│   ├── ASOC_PRD_v1.md
│   ├── ASOC_Market_Research_v1.md
│   └── plans/
│       ├── 2026-02-19-prd-refinement-design.md
│       └── 2026-02-19-phase-1-foundation.md
├── docker/
│   ├── nginx/
│   │   ├── nginx.conf
│   │   ├── nginx.dev.conf
│   │   └── certs/                     # mkcert certificates (gitignored)
│   ├── postgres/
│   │   └── init.sql
│   └── scripts/
│       └── setup-certs.sh             # mkcert certificate generation
├── backend/
│   ├── CLAUDE.md                      # Backend conventions
│   ├── Cargo.toml
│   ├── Cargo.lock
│   ├── .env.example
│   ├── sqlx-data.json
│   ├── src/
│   │   ├── main.rs
│   │   ├── lib.rs
│   │   ├── config/
│   │   │   └── mod.rs                 # App configuration
│   │   ├── errors/
│   │   │   └── mod.rs                 # Error types and handling
│   │   ├── db/
│   │   │   ├── mod.rs
│   │   │   └── migrations/            # SQLx migrations
│   │   ├── models/
│   │   │   ├── mod.rs
│   │   │   ├── finding.rs             # Core finding model
│   │   │   ├── finding_sast.rs        # SAST-specific layer
│   │   │   ├── finding_sca.rs         # SCA-specific layer
│   │   │   ├── finding_dast.rs        # DAST-specific layer
│   │   │   ├── application.rs         # Application registry model
│   │   │   ├── user.rs                # User model
│   │   │   └── audit.rs               # Audit log model
│   │   ├── routes/
│   │   │   ├── mod.rs
│   │   │   ├── health.rs
│   │   │   ├── auth.rs
│   │   │   ├── users.rs
│   │   │   ├── findings.rs
│   │   │   ├── applications.rs
│   │   │   └── ingestion.rs
│   │   ├── services/
│   │   │   ├── mod.rs
│   │   │   ├── auth.rs
│   │   │   ├── finding.rs
│   │   │   ├── application.rs
│   │   │   ├── ingestion.rs
│   │   │   ├── deduplication.rs
│   │   │   ├── fingerprint.rs
│   │   │   ├── lifecycle.rs
│   │   │   └── risk_score.rs
│   │   ├── parsers/
│   │   │   ├── mod.rs                 # Parser trait definition
│   │   │   ├── sonarqube.rs           # SonarQube file parser
│   │   │   └── sarif.rs               # SARIF parser
│   │   └── middleware/
│   │       ├── mod.rs
│   │       ├── auth.rs                # JWT/session validation
│   │       └── rbac.rs                # Role-based access control
│   └── tests/
│       ├── common/
│       │   └── mod.rs                 # Test helpers, fixtures
│       ├── api/
│       │   ├── health_test.rs
│       │   ├── auth_test.rs
│       │   ├── findings_test.rs
│       │   ├── applications_test.rs
│       │   └── ingestion_test.rs
│       ├── services/
│       │   ├── deduplication_test.rs
│       │   ├── fingerprint_test.rs
│       │   ├── lifecycle_test.rs
│       │   └── risk_score_test.rs
│       └── parsers/
│           ├── sonarqube_test.rs
│           └── sarif_test.rs
└── frontend/
    ├── CLAUDE.md                      # Frontend conventions
    ├── package.json
    ├── vite.config.ts
    ├── tsconfig.json
    ├── tailwind.config.ts
    ├── components.json                # shadcn/ui config
    ├── index.html
    ├── public/
    │   └── locales/
    │       ├── en/
    │       │   └── translation.json
    │       └── it/
    │           └── translation.json
    ├── src/
    │   ├── main.tsx
    │   ├── App.tsx
    │   ├── i18n.ts
    │   ├── api/
    │   │   ├── client.ts              # API client (fetch wrapper)
    │   │   ├── auth.ts
    │   │   ├── findings.ts
    │   │   ├── applications.ts
    │   │   └── ingestion.ts
    │   ├── components/
    │   │   ├── ui/                     # shadcn/ui components
    │   │   ├── layout/
    │   │   │   ├── AppLayout.tsx
    │   │   │   ├── Sidebar.tsx
    │   │   │   ├── Header.tsx
    │   │   │   └── ThemeToggle.tsx
    │   │   ├── findings/
    │   │   │   ├── FindingList.tsx
    │   │   │   ├── FindingDetail.tsx
    │   │   │   ├── FindingFilters.tsx
    │   │   │   ├── FindingStatusBadge.tsx
    │   │   │   └── FindingTransitionDialog.tsx
    │   │   ├── applications/
    │   │   │   ├── ApplicationList.tsx
    │   │   │   ├── ApplicationDetail.tsx
    │   │   │   └── ApplicationForm.tsx
    │   │   ├── ingestion/
    │   │   │   ├── FileUpload.tsx
    │   │   │   └── IngestionHistory.tsx
    │   │   └── auth/
    │   │       ├── LoginForm.tsx
    │   │       └── ProtectedRoute.tsx
    │   ├── hooks/
    │   │   ├── useAuth.ts
    │   │   ├── useFindings.ts
    │   │   └── useApplications.ts
    │   ├── pages/
    │   │   ├── LoginPage.tsx
    │   │   ├── DashboardPage.tsx
    │   │   ├── FindingsPage.tsx
    │   │   ├── FindingDetailPage.tsx
    │   │   ├── ApplicationsPage.tsx
    │   │   ├── ApplicationDetailPage.tsx
    │   │   ├── IngestionPage.tsx
    │   │   ├── TriageQueuePage.tsx
    │   │   └── UnmappedAppsPage.tsx
    │   ├── stores/
    │   │   └── authStore.ts
    │   ├── types/
    │   │   ├── finding.ts
    │   │   ├── application.ts
    │   │   ├── user.ts
    │   │   └── api.ts
    │   └── lib/
    │       └── utils.ts               # shadcn/ui utility
    └── tests/
        ├── setup.ts
        ├── components/
        └── e2e/
```

---

## Section A: Project Setup

### Task 1: Create CLAUDE.md and Project Configuration Files

**Files:**
- Create: `CLAUDE.md`
- Create: `.gitignore`
- Create: `.env.example`
- Create: `LICENSE`
- Create: `Makefile`

**Step 1: Create root CLAUDE.md**

```markdown
# SynApSec — Application Security Orchestration and Correlation Platform

## Project Overview
Enterprise ASOC platform unifying findings from SAST (SonarQube), SCA (JFrog Xray),
and DAST (Tenable WAS) into a single pane of glass with deduplication, correlation,
risk-based prioritization, and workflow management.

## Tech Stack
- **Backend:** Rust (Axum, SQLx, Tower, Tokio)
- **Frontend:** React + TypeScript (Vite, TailwindCSS, shadcn/ui)
- **Database:** PostgreSQL 16+ (JSONB, full-text search)
- **Cache:** Redis
- **Proxy:** Nginx
- **Containers:** Docker Compose
- **HTTPS:** Everywhere (mkcert for local dev)

## Repository Structure
- `/backend` — Rust API server
- `/frontend` — React SPA
- `/docker` — Docker configs, Nginx, init scripts
- `/docs` — PRD, design docs, plans

## Development Commands
- `make dev` — Start all services (Docker Compose)
- `make test` — Run all tests (backend + frontend)
- `make test-backend` — Run Rust tests only
- `make test-frontend` — Run frontend tests only
- `make lint` — Run linters (clippy + eslint)
- `make migrate` — Run database migrations
- `make setup-certs` — Generate mkcert certificates

## Coding Conventions

### Rust (Backend)
- All code must pass `cargo clippy` with no warnings
- Use `thiserror` for error types, `anyhow` only in main/tests
- All public API types derive `Serialize`, `Deserialize`
- Database queries use SQLx compile-time checked queries where possible
- All endpoints return consistent JSON envelope: `{ "data": ..., "error": null }`
- Error responses: `{ "data": null, "error": { "code": "...", "message": "..." } }`
- Never log sensitive data (passwords, API keys, finding details in error messages)
- All timestamps in UTC, stored as `timestamptz` in PostgreSQL
- UUIDs for all primary keys (v7 for time-ordered, v4 for random)

### TypeScript (Frontend)
- Strict TypeScript — no `any` types
- React functional components only
- Use TanStack Router for routing
- API calls through typed client in `src/api/`
- All user-facing strings through i18n (`useTranslation` hook)
- shadcn/ui components in `src/components/ui/`
- Custom components colocated by feature domain
- Prefer `const` over `let`, never use `var`

### Testing
- Backend: `cargo test` — unit tests in same file, integration tests in `/tests`
- Frontend: Vitest + React Testing Library for component tests
- Minimum 80% coverage for core business logic (models, services, parsers)
- All parsers must have integration tests with fixture files

### Git
- Branch from `main`, PR back to `main` (GitHub Flow)
- Commit messages: conventional commits (`feat:`, `fix:`, `test:`, `chore:`, `docs:`)
- Never commit secrets, .env files, or certificates
- Never reference AI tools in commit messages

### Security
- HTTPS enforced everywhere including local dev
- Passwords hashed with argon2id
- API authentication via JWT (short-lived access + refresh token)
- RBAC enforced at middleware level — every route has a required role
- All user input validated before processing
- SQL injection prevented by SQLx parameterized queries
- XSS prevented by React's default escaping + CSP headers
- No finding data or credentials in logs
```

**Step 2: Create .gitignore**

```gitignore
# Rust
/backend/target/
**/*.rs.bk

# Node
/frontend/node_modules/
/frontend/dist/
/frontend/.vite/

# Environment
.env
.env.local
.env.*.local

# Certificates (generated by mkcert)
/docker/nginx/certs/

# IDE
.idea/
.vscode/
*.swp
*.swo
*~

# OS
.DS_Store
Thumbs.db

# Docker volumes
postgres_data/
redis_data/

# Test coverage
/backend/tarpaulin-report.html
/backend/lcov.info
/frontend/coverage/

# SQLx offline mode
# Keep sqlx-data.json committed for CI
```

**Step 3: Create .env.example**

```env
# Database
DATABASE_URL=postgresql://synapsec:synapsec_dev@localhost:5432/synapsec
DATABASE_MAX_CONNECTIONS=10

# Redis
REDIS_URL=redis://localhost:6379

# Backend
BACKEND_HOST=0.0.0.0
BACKEND_PORT=3000
RUST_LOG=synapsec=debug,tower_http=debug

# JWT
JWT_SECRET=change-this-to-a-secure-random-string-in-production
JWT_ACCESS_TOKEN_EXPIRY_SECS=900
JWT_REFRESH_TOKEN_EXPIRY_SECS=604800

# Frontend URL (for CORS)
FRONTEND_URL=https://localhost:5173

# TLS (local dev)
TLS_CERT_PATH=../docker/nginx/certs/localhost+2.pem
TLS_KEY_PATH=../docker/nginx/certs/localhost+2-key.pem
```

**Step 4: Create LICENSE**

Select appropriate license (recommend MIT or Apache-2.0 for internal enterprise tooling; confirm with user if needed). Create a standard MIT LICENSE file.

**Step 5: Create Makefile**

```makefile
.PHONY: dev dev-down test test-backend test-frontend lint migrate setup-certs

# Development
dev:
	docker compose -f docker-compose.yml -f docker-compose.dev.yml up --build

dev-down:
	docker compose -f docker-compose.yml -f docker-compose.dev.yml down

# Testing
test: test-backend test-frontend

test-backend:
	cd backend && cargo test

test-frontend:
	cd frontend && npm test

# Linting
lint:
	cd backend && cargo clippy -- -D warnings
	cd frontend && npm run lint

# Database
migrate:
	cd backend && sqlx migrate run

# Certificates
setup-certs:
	./docker/scripts/setup-certs.sh
```

**Step 6: Commit**

```bash
git add CLAUDE.md .gitignore .env.example LICENSE Makefile
git commit -m "chore: add project configuration files and CLAUDE.md"
```

---

### Task 2: Docker Compose and Infrastructure Setup

**Files:**
- Create: `docker-compose.yml`
- Create: `docker-compose.dev.yml`
- Create: `docker/nginx/nginx.dev.conf`
- Create: `docker/postgres/init.sql`
- Create: `docker/scripts/setup-certs.sh`

**Step 1: Create mkcert setup script**

```bash
#!/usr/bin/env bash
set -euo pipefail

CERT_DIR="$(dirname "$0")/../nginx/certs"
mkdir -p "$CERT_DIR"

if ! command -v mkcert &> /dev/null; then
    echo "Error: mkcert is not installed. Install it first:"
    echo "  https://github.com/FiloSottile/mkcert#installation"
    exit 1
fi

# Install local CA if not already done
mkcert -install

# Generate certificates for local development
mkcert -cert-file "$CERT_DIR/localhost+2.pem" \
       -key-file "$CERT_DIR/localhost+2-key.pem" \
       localhost 127.0.0.1 ::1

echo "Certificates generated in $CERT_DIR"
```

**Step 2: Create PostgreSQL init script**

```sql
-- Create extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- The application will manage its own schema via SQLx migrations.
-- This file only handles extensions that require superuser privileges.
```

**Step 3: Create docker-compose.yml (base)**

```yaml
services:
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: synapsec
      POSTGRES_USER: synapsec
      POSTGRES_PASSWORD: synapsec_dev
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./docker/postgres/init.sql:/docker-entrypoint-initdb.d/init.sql
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U synapsec"]
      interval: 5s
      timeout: 5s
      retries: 5

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 5s
      timeout: 5s
      retries: 5

volumes:
  postgres_data:
  redis_data:
```

**Step 4: Create docker-compose.dev.yml (dev overrides)**

```yaml
services:
  nginx:
    image: nginx:alpine
    ports:
      - "443:443"
    volumes:
      - ./docker/nginx/nginx.dev.conf:/etc/nginx/nginx.conf:ro
      - ./docker/nginx/certs:/etc/nginx/certs:ro
    depends_on:
      - backend
      - frontend

  backend:
    build:
      context: ./backend
      dockerfile: Dockerfile.dev
    ports:
      - "3000:3000"
    environment:
      DATABASE_URL: postgresql://synapsec:synapsec_dev@postgres:5432/synapsec
      REDIS_URL: redis://redis:6379
      RUST_LOG: synapsec=debug,tower_http=debug
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    volumes:
      - ./backend/src:/app/src
      - backend_target:/app/target

  frontend:
    build:
      context: ./frontend
      dockerfile: Dockerfile.dev
    ports:
      - "5173:5173"
    volumes:
      - ./frontend/src:/app/src
      - ./frontend/public:/app/public
      - frontend_node_modules:/app/node_modules

volumes:
  backend_target:
  frontend_node_modules:
```

**Step 5: Create Nginx dev configuration**

```nginx
events {
    worker_connections 1024;
}

http {
    upstream backend {
        server backend:3000;
    }

    upstream frontend {
        server frontend:5173;
    }

    server {
        listen 443 ssl;
        server_name localhost;

        ssl_certificate /etc/nginx/certs/localhost+2.pem;
        ssl_certificate_key /etc/nginx/certs/localhost+2-key.pem;
        ssl_protocols TLSv1.2 TLSv1.3;

        # API routes
        location /api/ {
            proxy_pass http://backend;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        # Health check
        location /health/ {
            proxy_pass http://backend;
        }

        # Frontend (Vite dev server with HMR)
        location / {
            proxy_pass http://frontend;
            proxy_set_header Host $host;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
        }
    }
}
```

**Step 6: Commit**

```bash
git add docker-compose.yml docker-compose.dev.yml docker/ Makefile
git commit -m "chore: add Docker Compose infrastructure and Nginx config"
```

---

### Task 3: Backend Scaffolding (Rust/Axum Project)

**Files:**
- Create: `backend/Cargo.toml`
- Create: `backend/src/main.rs`
- Create: `backend/src/lib.rs`
- Create: `backend/src/config/mod.rs`
- Create: `backend/CLAUDE.md`
- Create: `backend/Dockerfile.dev`

**Step 1: Initialize Rust project and write Cargo.toml**

```toml
[package]
name = "synapsec"
version = "0.1.0"
edition = "2021"
rust-version = "1.75"

[dependencies]
# Web framework
axum = { version = "0.8", features = ["macros", "multipart"] }
axum-extra = { version = "0.10", features = ["typed-header", "cookie"] }
tower = { version = "0.5", features = ["full"] }
tower-http = { version = "0.6", features = ["cors", "trace", "limit", "compression-gzip"] }
tokio = { version = "1", features = ["full"] }
hyper = { version = "1" }

# Database
sqlx = { version = "0.8", features = ["runtime-tokio", "tls-rustls", "postgres", "uuid", "chrono", "json", "migrate"] }

# Serialization
serde = { version = "1", features = ["derive"] }
serde_json = "1"

# Auth
argon2 = "0.5"
jsonwebtoken = "9"

# Utils
uuid = { version = "1", features = ["v4", "v7", "serde"] }
chrono = { version = "0.4", features = ["serde"] }
thiserror = "2"
anyhow = "1"
dotenvy = "0.15"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter", "json"] }
sha2 = "0.10"
hex = "0.4"
validator = { version = "0.19", features = ["derive"] }

# Redis
redis = { version = "0.27", features = ["tokio-comp"] }

# CSV/SARIF parsing
csv = "1"
quick-xml = "0.37"

[dev-dependencies]
reqwest = { version = "0.12", features = ["json"] }
tokio-test = "0.4"
sqlx = { version = "0.8", features = ["runtime-tokio", "tls-rustls", "postgres", "uuid", "chrono", "json", "migrate"] }
tempfile = "3"
```

Note: Pin exact versions at implementation time based on latest stable releases. The versions above are indicative.

**Step 2: Create config module**

```rust
// backend/src/config/mod.rs
use std::env;

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub database_url: String,
    pub database_max_connections: u32,
    pub redis_url: String,
    pub host: String,
    pub port: u16,
    pub jwt_secret: String,
    pub jwt_access_token_expiry_secs: i64,
    pub jwt_refresh_token_expiry_secs: i64,
    pub frontend_url: String,
}

impl AppConfig {
    pub fn from_env() -> Result<Self, env::VarError> {
        Ok(Self {
            database_url: env::var("DATABASE_URL")?,
            database_max_connections: env::var("DATABASE_MAX_CONNECTIONS")
                .unwrap_or_else(|_| "10".to_string())
                .parse()
                .unwrap_or(10),
            redis_url: env::var("REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379".to_string()),
            host: env::var("BACKEND_HOST").unwrap_or_else(|_| "0.0.0.0".to_string()),
            port: env::var("BACKEND_PORT")
                .unwrap_or_else(|_| "3000".to_string())
                .parse()
                .unwrap_or(3000),
            jwt_secret: env::var("JWT_SECRET")?,
            jwt_access_token_expiry_secs: env::var("JWT_ACCESS_TOKEN_EXPIRY_SECS")
                .unwrap_or_else(|_| "900".to_string())
                .parse()
                .unwrap_or(900),
            jwt_refresh_token_expiry_secs: env::var("JWT_REFRESH_TOKEN_EXPIRY_SECS")
                .unwrap_or_else(|_| "604800".to_string())
                .parse()
                .unwrap_or(604800),
            frontend_url: env::var("FRONTEND_URL")
                .unwrap_or_else(|_| "https://localhost:5173".to_string()),
        })
    }
}
```

**Step 3: Create lib.rs with app builder**

```rust
// backend/src/lib.rs
pub mod config;

// These modules will be added as we build them:
// pub mod db;
// pub mod errors;
// pub mod models;
// pub mod routes;
// pub mod services;
// pub mod parsers;
// pub mod middleware;
```

**Step 4: Create main.rs**

```rust
// backend/src/main.rs
use std::net::SocketAddr;
use synapsec::config::AppConfig;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load .env file
    dotenvy::dotenv().ok();

    // Initialize structured logging (JSON format)
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| "synapsec=debug,tower_http=debug".into()))
        .with(tracing_subscriber::fmt::layer().json())
        .init();

    let config = AppConfig::from_env().expect("Failed to load configuration");

    let addr = SocketAddr::from(([0, 0, 0, 0], config.port));
    tracing::info!("Starting SynApSec API server on {}", addr);

    // Placeholder — will be replaced with full app setup
    let app = axum::Router::new()
        .route("/health/live", axum::routing::get(|| async { "OK" }));

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
```

**Step 5: Create backend CLAUDE.md**

```markdown
# SynApSec Backend

## Stack
Rust, Axum 0.8, SQLx (PostgreSQL), Tower, Tokio

## Architecture
- `src/config/` — Configuration from environment variables
- `src/errors/` — Unified error types using `thiserror`
- `src/models/` — Database models (SQLx `FromRow` structs)
- `src/routes/` — Axum route handlers (thin — delegate to services)
- `src/services/` — Business logic (testable without HTTP)
- `src/parsers/` — Scanner output parsers (implement `Parser` trait)
- `src/middleware/` — Auth, RBAC, request logging

## Patterns
- Route handlers are thin: validate input → call service → return response
- Services contain business logic and are the primary test target
- All database access goes through services, never directly from routes
- Use `AppState` (shared via Axum state) for db pool, redis, config
- Every API response uses `ApiResponse<T>` envelope
- All IDs are UUIDs (v7 for time-ordered entities, v4 for random)
- Timestamps are always UTC `chrono::DateTime<Utc>`, stored as `timestamptz`

## Running
```bash
cargo run         # Start server
cargo test        # Run all tests
cargo clippy      # Lint
```

## Database Migrations
```bash
sqlx migrate add <name>   # Create new migration
sqlx migrate run          # Apply migrations
```
```

**Step 6: Create dev Dockerfile**

```dockerfile
# backend/Dockerfile.dev
FROM rust:1.83-slim-bookworm

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

# Copy manifests first for dependency caching
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs && cargo build && rm -rf src

# Copy source
COPY . .

# Run with cargo watch for hot reload (install if not present)
RUN cargo install cargo-watch

CMD ["cargo", "watch", "-x", "run"]
```

**Step 7: Verify the project compiles**

Run: `cd backend && cargo check`
Expected: Compiles successfully with no errors.

**Step 8: Commit**

```bash
git add backend/
git commit -m "chore: scaffold Rust/Axum backend project"
```

---

### Task 4: Frontend Scaffolding (React/Vite Project)

**Files:**
- Create: `frontend/` (via Vite scaffold)
- Create: `frontend/CLAUDE.md`
- Create: `frontend/Dockerfile.dev`
- Modify: `frontend/vite.config.ts` (add HTTPS)
- Configure: TailwindCSS, shadcn/ui, react-i18next

**Step 1: Initialize Vite React TypeScript project**

Run: `npm create vite@latest frontend -- --template react-ts`

**Step 2: Install dependencies**

```bash
cd frontend
npm install
npm install -D tailwindcss @tailwindcss/vite
npm install react-i18next i18next
npm install @tanstack/react-router @tanstack/react-table
npm install lucide-react class-variance-authority clsx tailwind-merge
```

**Step 3: Initialize shadcn/ui**

Run: `npx shadcn@latest init`

Select: TypeScript, Default style, CSS variables for colors, `src/lib/utils.ts` for utils.

Then install base components:
```bash
npx shadcn@latest add button input label card table badge dialog dropdown-menu
npx shadcn@latest add select tabs toast separator sheet command
```

**Step 4: Configure Vite for HTTPS**

```typescript
// frontend/vite.config.ts
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import fs from 'fs'
import path from 'path'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: 5173,
    https: {
      key: fs.readFileSync(path.resolve(__dirname, '../docker/nginx/certs/localhost+2-key.pem')),
      cert: fs.readFileSync(path.resolve(__dirname, '../docker/nginx/certs/localhost+2.pem')),
    },
    proxy: {
      '/api': {
        target: 'https://localhost:3000',
        secure: false,
      },
    },
  },
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
})
```

Note: When running in Docker, HTTPS is handled by Nginx and the Vite config should skip the `https` block. Use an environment variable to toggle.

**Step 5: Set up i18n**

```typescript
// frontend/src/i18n.ts
import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';

import en from '../public/locales/en/translation.json';
import it from '../public/locales/it/translation.json';

i18n.use(initReactI18next).init({
  resources: {
    en: { translation: en },
    it: { translation: it },
  },
  lng: 'en',
  fallbackLng: 'en',
  interpolation: {
    escapeValue: false,
  },
});

export default i18n;
```

```json
// frontend/public/locales/en/translation.json
{
  "app": {
    "title": "SynApSec",
    "subtitle": "Application Security Orchestration"
  },
  "nav": {
    "dashboard": "Dashboard",
    "findings": "Findings",
    "applications": "Applications",
    "ingestion": "Ingestion",
    "triage": "Triage Queue",
    "unmapped": "Unmapped Apps"
  },
  "auth": {
    "login": "Sign In",
    "logout": "Sign Out",
    "username": "Username",
    "password": "Password"
  },
  "common": {
    "save": "Save",
    "cancel": "Cancel",
    "delete": "Delete",
    "edit": "Edit",
    "search": "Search",
    "filter": "Filter",
    "loading": "Loading...",
    "noResults": "No results found"
  }
}
```

```json
// frontend/public/locales/it/translation.json
{
  "app": {
    "title": "SynApSec",
    "subtitle": "Orchestrazione della Sicurezza Applicativa"
  },
  "nav": {
    "dashboard": "Dashboard",
    "findings": "Risultati",
    "applications": "Applicazioni",
    "ingestion": "Importazione",
    "triage": "Coda di Triage",
    "unmapped": "App Non Mappate"
  },
  "auth": {
    "login": "Accedi",
    "logout": "Esci",
    "username": "Nome utente",
    "password": "Password"
  },
  "common": {
    "save": "Salva",
    "cancel": "Annulla",
    "delete": "Elimina",
    "edit": "Modifica",
    "search": "Cerca",
    "filter": "Filtra",
    "loading": "Caricamento...",
    "noResults": "Nessun risultato trovato"
  }
}
```

**Step 6: Create frontend CLAUDE.md**

```markdown
# SynApSec Frontend

## Stack
React 18+, TypeScript (strict), Vite, TailwindCSS, shadcn/ui

## Architecture
- `src/api/` — Typed API client functions (one file per domain)
- `src/components/` — Reusable components organized by domain
- `src/components/ui/` — shadcn/ui primitives (do not modify directly)
- `src/hooks/` — Custom React hooks
- `src/pages/` — Page-level components (one per route)
- `src/stores/` — Client-side state (auth, preferences)
- `src/types/` — TypeScript type definitions matching API contracts
- `src/lib/` — Utility functions
- `public/locales/` — i18n translation files (en, it)

## Patterns
- All user-facing strings through `useTranslation()` — never hardcoded
- API calls always through typed functions in `src/api/`
- shadcn/ui for all base components — customize via className, never modify source
- TanStack Table for all data tables (findings, applications)
- TanStack Router for type-safe routing
- Custom fonts and design tokens in tailwind.config.ts
- Light/dark theme via CSS variables + ThemeToggle component

## Running
```bash
npm run dev       # Start dev server (HTTPS)
npm test          # Run Vitest
npm run lint      # ESLint
npm run build     # Production build
```
```

**Step 7: Create dev Dockerfile**

```dockerfile
# frontend/Dockerfile.dev
FROM node:22-alpine

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY . .

EXPOSE 5173

CMD ["npm", "run", "dev", "--", "--host"]
```

**Step 8: Verify frontend starts**

Run: `cd frontend && npm run dev`
Expected: Vite dev server starts on https://localhost:5173 (after mkcert setup).

**Step 9: Commit**

```bash
git add frontend/
git commit -m "chore: scaffold React/TypeScript frontend with TailwindCSS, shadcn/ui, i18n"
```

---

### Task 5: Verify Full Stack Docker Compose Starts

**Step 1: Generate certificates**

Run: `chmod +x docker/scripts/setup-certs.sh && ./docker/scripts/setup-certs.sh`
Expected: Certificates generated in `docker/nginx/certs/`.

**Step 2: Start all services**

Run: `make dev`
Expected: PostgreSQL, Redis, backend, frontend, and Nginx all start. Nginx serves on https://localhost:443.

**Step 3: Verify health endpoint**

Run: `curl -k https://localhost/health/live`
Expected: `OK`

**Step 4: Verify frontend**

Open: `https://localhost` in browser.
Expected: Default Vite React page loads over HTTPS.

**Step 5: Commit any adjustments**

```bash
git add -A
git commit -m "chore: verify full stack Docker Compose setup"
```

---

## Section B: Database Schema & Core Models

### Task 6: Database Migration Setup and Core Schema

**Files:**
- Create: `backend/migrations/001_initial_schema.sql`
- Create: `backend/src/db/mod.rs`

**Step 1: Create database module**

```rust
// backend/src/db/mod.rs
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

pub async fn create_pool(database_url: &str, max_connections: u32) -> Result<PgPool, sqlx::Error> {
    PgPoolOptions::new()
        .max_connections(max_connections)
        .connect(database_url)
        .await
}
```

**Step 2: Create initial migration**

Run: `cd backend && sqlx migrate add initial_schema`

This creates a timestamped migration file. Write the following SQL:

```sql
-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ============================================================
-- ENUM TYPES
-- ============================================================

CREATE TYPE finding_category AS ENUM ('SAST', 'SCA', 'DAST');

CREATE TYPE finding_status AS ENUM (
    'New',
    'Confirmed',
    'In_Remediation',
    'Mitigated',
    'Verified',
    'Closed',
    'False_Positive_Requested',
    'False_Positive',
    'Risk_Accepted',
    'Deferred_Remediation',
    'Invalidated'
);

CREATE TYPE severity_level AS ENUM ('Critical', 'High', 'Medium', 'Low', 'Info');

CREATE TYPE sla_status AS ENUM ('On_Track', 'At_Risk', 'Breached');

CREATE TYPE confidence_level AS ENUM ('High', 'Medium', 'Low');

CREATE TYPE asset_criticality AS ENUM (
    'Very_High', 'High', 'Medium_High', 'Medium', 'Medium_Low', 'Low'
);

CREATE TYPE asset_tier AS ENUM ('Tier_1', 'Tier_2', 'Tier_3');

CREATE TYPE exposure_level AS ENUM ('Internet_Facing', 'DMZ', 'Internal', 'Dev_Test');

CREATE TYPE data_classification AS ENUM ('Public', 'Internal', 'Confidential', 'Restricted');

CREATE TYPE app_status AS ENUM ('Active', 'Deprecated', 'Decommissioned');

CREATE TYPE user_role AS ENUM (
    'Platform_Admin',
    'AppSec_Analyst',
    'AppSec_Manager',
    'Developer',
    'Executive',
    'Auditor',
    'API_Service_Account'
);

CREATE TYPE relationship_type AS ENUM (
    'duplicate_of',
    'correlated_with',
    'grouped_under',
    'superseded_by'
);

CREATE TYPE dependency_type AS ENUM ('Direct', 'Transitive');

CREATE TYPE exploit_maturity AS ENUM ('Proof_of_Concept', 'Functional', 'Weaponized', 'Unknown');

-- ============================================================
-- USERS TABLE
-- ============================================================

CREATE TABLE users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username        VARCHAR(255) NOT NULL UNIQUE,
    email           VARCHAR(255) NOT NULL UNIQUE,
    password_hash   VARCHAR(255) NOT NULL,
    display_name    VARCHAR(255) NOT NULL,
    role            user_role NOT NULL,
    is_active       BOOLEAN NOT NULL DEFAULT true,
    failed_login_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until    TIMESTAMPTZ,
    last_login      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_email ON users(email);

-- ============================================================
-- APPLICATIONS TABLE
-- ============================================================

CREATE TABLE applications (
    id                          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    app_name                    VARCHAR(255) NOT NULL,
    app_code                    VARCHAR(10) NOT NULL UNIQUE,
    description                 TEXT,
    criticality                 asset_criticality DEFAULT 'Medium',
    tier                        asset_tier NOT NULL DEFAULT 'Tier_2',
    business_unit               VARCHAR(255),
    business_owner              VARCHAR(255),
    technical_owner             VARCHAR(255),
    security_champion           VARCHAR(255),
    technology_stack            JSONB DEFAULT '[]'::JSONB,
    deployment_environment      JSONB DEFAULT '[]'::JSONB,
    exposure                    exposure_level,
    data_classification         data_classification,
    regulatory_scope            JSONB DEFAULT '[]'::JSONB,
    repository_urls             JSONB DEFAULT '[]'::JSONB,
    scanner_project_ids         JSONB DEFAULT '{}'::JSONB,
    status                      app_status NOT NULL DEFAULT 'Active',
    is_verified                 BOOLEAN NOT NULL DEFAULT true,

    -- Corporate APM enrichment (Section 2.3 of design doc)
    ssa_code                    VARCHAR(50),
    ssa_name                    VARCHAR(255),
    functional_reference_email  VARCHAR(255),
    technical_reference_email   VARCHAR(255),
    effective_office_owner      VARCHAR(255),
    effective_office_name       VARCHAR(255),
    confidentiality_level       VARCHAR(50),
    integrity_level             VARCHAR(50),
    availability_level          VARCHAR(50),
    is_dora_fei                 BOOLEAN DEFAULT false,
    is_gdpr_subject             BOOLEAN DEFAULT false,
    has_pci_data                BOOLEAN DEFAULT false,
    is_psd2_relevant            BOOLEAN DEFAULT false,
    apm_metadata                JSONB DEFAULT '{}'::JSONB,

    created_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_applications_app_code ON applications(app_code);
CREATE INDEX idx_applications_status ON applications(status);
CREATE INDEX idx_applications_criticality ON applications(criticality);
CREATE INDEX idx_applications_ssa_code ON applications(ssa_code);
CREATE INDEX idx_applications_is_verified ON applications(is_verified) WHERE NOT is_verified;

-- ============================================================
-- FINDINGS TABLE (Core Layer)
-- ============================================================

CREATE TABLE findings (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_tool             VARCHAR(100) NOT NULL,
    source_tool_version     VARCHAR(50),
    source_finding_id       VARCHAR(500) NOT NULL,
    finding_category        finding_category NOT NULL,
    title                   VARCHAR(1000) NOT NULL,
    description             TEXT NOT NULL,
    normalized_severity     severity_level NOT NULL,
    original_severity       VARCHAR(100) NOT NULL,
    cvss_score              REAL,
    cvss_vector             VARCHAR(255),
    cwe_ids                 JSONB DEFAULT '[]'::JSONB,
    cve_ids                 JSONB DEFAULT '[]'::JSONB,
    owasp_category          VARCHAR(100),
    status                  finding_status NOT NULL DEFAULT 'New',
    composite_risk_score    REAL,
    confidence              confidence_level,
    fingerprint             VARCHAR(128) NOT NULL,
    application_id          UUID REFERENCES applications(id),
    remediation_owner       VARCHAR(255),
    office_owner            VARCHAR(255),
    office_manager          VARCHAR(255),
    first_seen              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    status_changed_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    sla_due_date            TIMESTAMPTZ,
    sla_status              sla_status,
    tags                    JSONB DEFAULT '[]'::JSONB,
    remediation_guidance    TEXT,
    raw_finding             JSONB NOT NULL,
    metadata                JSONB DEFAULT '{}'::JSONB,

    -- Full-text search vector
    search_vector           TSVECTOR GENERATED ALWAYS AS (
        setweight(to_tsvector('english', coalesce(title, '')), 'A') ||
        setweight(to_tsvector('english', coalesce(description, '')), 'B')
    ) STORED
);

-- Performance indexes
CREATE INDEX idx_findings_fingerprint ON findings(fingerprint);
CREATE INDEX idx_findings_application_id ON findings(application_id);
CREATE INDEX idx_findings_status ON findings(status);
CREATE INDEX idx_findings_severity ON findings(normalized_severity);
CREATE INDEX idx_findings_category ON findings(finding_category);
CREATE INDEX idx_findings_source_tool ON findings(source_tool);
CREATE INDEX idx_findings_first_seen ON findings(first_seen);
CREATE INDEX idx_findings_last_seen ON findings(last_seen);
CREATE INDEX idx_findings_sla_status ON findings(sla_status);
CREATE INDEX idx_findings_composite_risk ON findings(composite_risk_score DESC NULLS LAST);

-- Full-text search index
CREATE INDEX idx_findings_search ON findings USING GIN(search_vector);

-- JSONB indexes for CWE/CVE lookups
CREATE INDEX idx_findings_cwe ON findings USING GIN(cwe_ids);
CREATE INDEX idx_findings_cve ON findings USING GIN(cve_ids);

-- Composite index for common queries
CREATE INDEX idx_findings_status_severity ON findings(status, normalized_severity);
CREATE INDEX idx_findings_app_status ON findings(application_id, status);

-- ============================================================
-- SAST-SPECIFIC LAYER
-- ============================================================

CREATE TABLE finding_sast (
    finding_id              UUID PRIMARY KEY REFERENCES findings(id) ON DELETE CASCADE,
    file_path               VARCHAR(1000) NOT NULL,
    line_number_start       INTEGER,
    line_number_end         INTEGER,
    project                 VARCHAR(255) NOT NULL,
    rule_name               VARCHAR(500) NOT NULL,
    rule_id                 VARCHAR(255) NOT NULL,
    issue_type              VARCHAR(100),
    branch                  VARCHAR(255),
    source_url              VARCHAR(2000),
    scanner_creation_date   TIMESTAMPTZ,
    baseline_date           TIMESTAMPTZ,
    last_analysis_date      TIMESTAMPTZ,
    code_snippet            TEXT,
    taint_source            VARCHAR(500),
    taint_sink              VARCHAR(500),
    language                VARCHAR(50),
    framework               VARCHAR(100),
    scanner_description     TEXT,
    scanner_tags            JSONB DEFAULT '[]'::JSONB,
    quality_gate            VARCHAR(255)
);

CREATE INDEX idx_sast_file_path ON finding_sast(file_path);
CREATE INDEX idx_sast_rule_id ON finding_sast(rule_id);
CREATE INDEX idx_sast_project ON finding_sast(project);

-- ============================================================
-- SCA-SPECIFIC LAYER
-- ============================================================

CREATE TABLE finding_sca (
    finding_id              UUID PRIMARY KEY REFERENCES findings(id) ON DELETE CASCADE,
    package_name            VARCHAR(500) NOT NULL,
    package_version         VARCHAR(100) NOT NULL,
    package_type            VARCHAR(50),
    fixed_version           VARCHAR(100),
    dependency_type         dependency_type,
    dependency_path         TEXT,
    license                 VARCHAR(255),
    license_risk            VARCHAR(50),
    sbom_reference          VARCHAR(500),
    epss_score              REAL,
    known_exploited         BOOLEAN DEFAULT false,
    exploit_maturity        exploit_maturity,
    affected_artifact       VARCHAR(500),
    build_project           VARCHAR(255)
);

CREATE INDEX idx_sca_package ON finding_sca(package_name, package_version);
CREATE INDEX idx_sca_cve ON finding_sca(finding_id);

-- ============================================================
-- DAST-SPECIFIC LAYER
-- ============================================================

CREATE TABLE finding_dast (
    finding_id              UUID PRIMARY KEY REFERENCES findings(id) ON DELETE CASCADE,
    target_url              VARCHAR(2000) NOT NULL,
    http_method             VARCHAR(10),
    parameter               VARCHAR(500),
    attack_vector           TEXT,
    request_evidence        TEXT,
    response_evidence       TEXT,
    authentication_required BOOLEAN,
    authentication_context  VARCHAR(500),
    web_application_name    VARCHAR(255),
    scan_policy             VARCHAR(255)
);

CREATE INDEX idx_dast_target_url ON finding_dast(target_url);

-- ============================================================
-- FINDING RELATIONSHIPS
-- ============================================================

CREATE TABLE finding_relationships (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_finding_id   UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    target_finding_id   UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    relationship_type   relationship_type NOT NULL,
    confidence          confidence_level,
    created_by          UUID REFERENCES users(id),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    notes               TEXT,

    UNIQUE(source_finding_id, target_finding_id, relationship_type)
);

CREATE INDEX idx_rel_source ON finding_relationships(source_finding_id);
CREATE INDEX idx_rel_target ON finding_relationships(target_finding_id);

-- ============================================================
-- FINDING HISTORY (Immutable Audit Trail)
-- ============================================================

CREATE TABLE finding_history (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id      UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    action          VARCHAR(100) NOT NULL,
    field_changed   VARCHAR(100),
    old_value       TEXT,
    new_value       TEXT,
    actor_id        UUID REFERENCES users(id),
    actor_name      VARCHAR(255) NOT NULL,
    justification   TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_history_finding ON finding_history(finding_id);
CREATE INDEX idx_history_created ON finding_history(created_at);

-- ============================================================
-- FINDING COMMENTS
-- ============================================================

CREATE TABLE finding_comments (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id      UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    author_id       UUID NOT NULL REFERENCES users(id),
    author_name     VARCHAR(255) NOT NULL,
    content         TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_comments_finding ON finding_comments(finding_id);

-- ============================================================
-- INGESTION LOG
-- ============================================================

CREATE TABLE ingestion_logs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_tool     VARCHAR(100) NOT NULL,
    ingestion_type  VARCHAR(50) NOT NULL,
    file_name       VARCHAR(500),
    total_records   INTEGER NOT NULL DEFAULT 0,
    new_findings    INTEGER NOT NULL DEFAULT 0,
    updated_findings INTEGER NOT NULL DEFAULT 0,
    duplicates      INTEGER NOT NULL DEFAULT 0,
    errors          INTEGER NOT NULL DEFAULT 0,
    quarantined     INTEGER NOT NULL DEFAULT 0,
    status          VARCHAR(50) NOT NULL DEFAULT 'in_progress',
    error_details   JSONB,
    started_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at    TIMESTAMPTZ,
    initiated_by    UUID REFERENCES users(id)
);

CREATE INDEX idx_ingestion_status ON ingestion_logs(status);
CREATE INDEX idx_ingestion_started ON ingestion_logs(started_at);

-- ============================================================
-- TRIAGE RULES
-- ============================================================

CREATE TABLE triage_rules (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            VARCHAR(255) NOT NULL,
    description     TEXT,
    conditions      JSONB NOT NULL,
    is_active       BOOLEAN NOT NULL DEFAULT true,
    priority        INTEGER NOT NULL DEFAULT 0,
    created_by      UUID REFERENCES users(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================
-- AUDIT LOG (System-wide)
-- ============================================================

CREATE TABLE audit_log (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    entity_type     VARCHAR(100) NOT NULL,
    entity_id       UUID,
    action          VARCHAR(100) NOT NULL,
    actor_id        UUID REFERENCES users(id),
    actor_name      VARCHAR(255) NOT NULL,
    details         JSONB,
    ip_address      VARCHAR(45),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_entity ON audit_log(entity_type, entity_id);
CREATE INDEX idx_audit_actor ON audit_log(actor_id);
CREATE INDEX idx_audit_created ON audit_log(created_at);

-- ============================================================
-- SCANNER API KEYS (encrypted, per-user)
-- ============================================================

CREATE TABLE scanner_api_keys (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    scanner_name    VARCHAR(100) NOT NULL,
    key_label       VARCHAR(255) NOT NULL,
    encrypted_key   TEXT NOT NULL,
    api_url         VARCHAR(2000),
    is_active       BOOLEAN NOT NULL DEFAULT true,
    last_used       TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE(user_id, scanner_name, key_label)
);

-- ============================================================
-- CONFIGURATION TABLE (key-value for system settings)
-- ============================================================

CREATE TABLE system_config (
    key             VARCHAR(255) PRIMARY KEY,
    value           JSONB NOT NULL,
    description     TEXT,
    updated_by      UUID REFERENCES users(id),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Seed default configuration
INSERT INTO system_config (key, value, description) VALUES
    ('criticality_tier_mapping', '{
        "Very_High": "Tier_1",
        "High": "Tier_1",
        "Medium_High": "Tier_2",
        "Medium": "Tier_2",
        "Medium_Low": "Tier_3",
        "Low": "Tier_3"
    }'::JSONB, 'Mapping from 6-level asset criticality to 3 internal tiers'),
    ('sla_matrix', '{
        "P1": {"Tier_1": 72, "Tier_2": 168, "Tier_3": 336},
        "P2": {"Tier_1": 168, "Tier_2": 336, "Tier_3": 720},
        "P3": {"Tier_1": 720, "Tier_2": 1440, "Tier_3": 2160},
        "P4": {"Tier_1": 2160, "Tier_2": 4320, "Tier_3": null},
        "P5": {"Tier_1": null, "Tier_2": null, "Tier_3": null}
    }'::JSONB, 'SLA hours by priority and tier'),
    ('risk_score_weights', '{
        "normalized_severity": 0.30,
        "asset_criticality": 0.25,
        "exploitability": 0.20,
        "finding_age": 0.15,
        "correlation_density": 0.10
    }'::JSONB, 'Risk score factor weights'),
    ('auto_confirm_enabled', 'true'::JSONB, 'Auto-confirm findings on ingestion (triage rules can override)');

-- ============================================================
-- UPDATED_AT TRIGGER
-- ============================================================

CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_applications_updated_at BEFORE UPDATE ON applications
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_findings_updated_at BEFORE UPDATE ON findings
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_triage_rules_updated_at BEFORE UPDATE ON triage_rules
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
```

**Step 3: Run migration**

Run: `cd backend && sqlx migrate run`
Expected: Migration applied successfully. All tables created.

**Step 4: Verify schema**

Run: `psql $DATABASE_URL -c "\dt"`
Expected: All tables listed (users, applications, findings, finding_sast, finding_sca, finding_dast, finding_relationships, finding_history, finding_comments, ingestion_logs, triage_rules, audit_log, scanner_api_keys, system_config).

**Step 5: Commit**

```bash
git add backend/migrations/ backend/src/db/
git commit -m "feat: add database schema with all core tables, indexes, and seed config"
```

---

### Task 7: Rust Model Structs

**Files:**
- Create: `backend/src/models/mod.rs`
- Create: `backend/src/models/finding.rs`
- Create: `backend/src/models/finding_sast.rs`
- Create: `backend/src/models/finding_sca.rs`
- Create: `backend/src/models/finding_dast.rs`
- Create: `backend/src/models/application.rs`
- Create: `backend/src/models/user.rs`
- Create: `backend/src/models/audit.rs`

Each model file defines:
1. The SQLx `FromRow` struct matching the database table
2. A `Create*` struct for inserts (without auto-generated fields)
3. An `Update*` struct with all fields optional
4. Response DTOs that exclude sensitive fields (e.g., password_hash)

**Step 1: Write the finding model with tests**

```rust
// backend/src/models/finding.rs
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

// -- Enums matching PostgreSQL --

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type, PartialEq)]
#[sqlx(type_name = "finding_category", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FindingCategory {
    Sast,
    Sca,
    Dast,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type, PartialEq)]
#[sqlx(type_name = "finding_status")]
pub enum FindingStatus {
    New,
    Confirmed,
    #[sqlx(rename = "In_Remediation")]
    InRemediation,
    Mitigated,
    Verified,
    Closed,
    #[sqlx(rename = "False_Positive_Requested")]
    FalsePositiveRequested,
    #[sqlx(rename = "False_Positive")]
    FalsePositive,
    #[sqlx(rename = "Risk_Accepted")]
    RiskAccepted,
    #[sqlx(rename = "Deferred_Remediation")]
    DeferredRemediation,
    Invalidated,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type, PartialEq)]
#[sqlx(type_name = "severity_level")]
pub enum SeverityLevel {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type, PartialEq)]
#[sqlx(type_name = "sla_status")]
pub enum SlaStatus {
    #[sqlx(rename = "On_Track")]
    OnTrack,
    #[sqlx(rename = "At_Risk")]
    AtRisk,
    Breached,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type, PartialEq)]
#[sqlx(type_name = "confidence_level")]
pub enum ConfidenceLevel {
    High,
    Medium,
    Low,
}

// -- Core Finding --

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Finding {
    pub id: Uuid,
    pub source_tool: String,
    pub source_tool_version: Option<String>,
    pub source_finding_id: String,
    pub finding_category: FindingCategory,
    pub title: String,
    pub description: String,
    pub normalized_severity: SeverityLevel,
    pub original_severity: String,
    pub cvss_score: Option<f32>,
    pub cvss_vector: Option<String>,
    pub cwe_ids: serde_json::Value,
    pub cve_ids: serde_json::Value,
    pub owasp_category: Option<String>,
    pub status: FindingStatus,
    pub composite_risk_score: Option<f32>,
    pub confidence: Option<ConfidenceLevel>,
    pub fingerprint: String,
    pub application_id: Option<Uuid>,
    pub remediation_owner: Option<String>,
    pub office_owner: Option<String>,
    pub office_manager: Option<String>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub status_changed_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub sla_due_date: Option<DateTime<Utc>>,
    pub sla_status: Option<SlaStatus>,
    pub tags: serde_json::Value,
    pub remediation_guidance: Option<String>,
    pub raw_finding: serde_json::Value,
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateFinding {
    pub source_tool: String,
    pub source_tool_version: Option<String>,
    pub source_finding_id: String,
    pub finding_category: FindingCategory,
    pub title: String,
    pub description: String,
    pub normalized_severity: SeverityLevel,
    pub original_severity: String,
    pub cvss_score: Option<f32>,
    pub cvss_vector: Option<String>,
    pub cwe_ids: Vec<String>,
    pub cve_ids: Vec<String>,
    pub owasp_category: Option<String>,
    pub confidence: Option<ConfidenceLevel>,
    pub fingerprint: String,
    pub application_id: Option<Uuid>,
    pub tags: Vec<String>,
    pub remediation_guidance: Option<String>,
    pub raw_finding: serde_json::Value,
    pub metadata: serde_json::Value,
}
```

Implement similar patterns for all model files. Each model follows the same structure: DB struct, Create struct, Update struct, Response DTO.

**Step 2: Write unit tests for enum serialization**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_finding_status_serialization() {
        let status = FindingStatus::InRemediation;
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(json, "\"InRemediation\"");
    }

    #[test]
    fn test_severity_ordering() {
        // Verify severity levels can be compared for risk scoring
        let severities = vec![
            SeverityLevel::Info,
            SeverityLevel::Low,
            SeverityLevel::Medium,
            SeverityLevel::High,
            SeverityLevel::Critical,
        ];
        assert_eq!(severities.len(), 5);
    }
}
```

**Step 3: Run tests**

Run: `cd backend && cargo test`
Expected: All model tests pass.

**Step 4: Commit**

```bash
git add backend/src/models/
git commit -m "feat: add Rust model structs for all database entities"
```

---

## Section C: Backend Foundation

### Task 8: Error Handling Module

**Files:**
- Create: `backend/src/errors/mod.rs`

**Step 1: Write error types**

```rust
// backend/src/errors/mod.rs
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct ApiError {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct ApiResponse<T: Serialize> {
    pub data: Option<T>,
    pub error: Option<ApiError>,
}

impl<T: Serialize> ApiResponse<T> {
    pub fn success(data: T) -> Json<Self> {
        Json(Self {
            data: Some(data),
            error: None,
        })
    }

    pub fn error(code: &str, message: &str) -> Json<Self> {
        Json(Self {
            data: None,
            error: Some(ApiError {
                code: code.to_string(),
                message: message.to_string(),
            }),
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Unauthorized")]
    Unauthorized,

    #[error("Forbidden: {0}")]
    Forbidden(String),

    #[error("Conflict: {0}")]
    Conflict(String),

    #[error("Invalid state transition: {0}")]
    InvalidTransition(String),

    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Internal error: {0}")]
    Internal(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, code, message) = match &self {
            AppError::NotFound(msg) => (StatusCode::NOT_FOUND, "NOT_FOUND", msg.clone()),
            AppError::Validation(msg) => (StatusCode::BAD_REQUEST, "VALIDATION_ERROR", msg.clone()),
            AppError::Unauthorized => (StatusCode::UNAUTHORIZED, "UNAUTHORIZED", "Authentication required".to_string()),
            AppError::Forbidden(msg) => (StatusCode::FORBIDDEN, "FORBIDDEN", msg.clone()),
            AppError::Conflict(msg) => (StatusCode::CONFLICT, "CONFLICT", msg.clone()),
            AppError::InvalidTransition(msg) => (StatusCode::BAD_REQUEST, "INVALID_TRANSITION", msg.clone()),
            AppError::Database(e) => {
                tracing::error!("Database error: {:?}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", "An internal error occurred".to_string())
            },
            AppError::Internal(msg) => {
                tracing::error!("Internal error: {}", msg);
                (StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", "An internal error occurred".to_string())
            },
        };

        let body = ApiResponse::<()> {
            data: None,
            error: Some(ApiError {
                code: code.to_string(),
                message,
            }),
        };

        (status, Json(body)).into_response()
    }
}
```

**Step 2: Write tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_response_success() {
        let response = ApiResponse::success("hello");
        let json = serde_json::to_value(&response.0).unwrap();
        assert_eq!(json["data"], "hello");
        assert!(json["error"].is_null());
    }

    #[test]
    fn test_api_response_error() {
        let response = ApiResponse::<()>::error("NOT_FOUND", "Item not found");
        let json = serde_json::to_value(&response.0).unwrap();
        assert!(json["data"].is_null());
        assert_eq!(json["error"]["code"], "NOT_FOUND");
    }
}
```

**Step 3: Run tests, commit**

```bash
cd backend && cargo test
git add backend/src/errors/
git commit -m "feat: add unified error handling with API response envelope"
```

---

### Task 9: Health Check Endpoints

**Files:**
- Create: `backend/src/routes/health.rs`
- Create: `backend/src/routes/mod.rs`
- Create: `backend/tests/api/health_test.rs`

**Step 1: Write failing test**

```rust
// backend/tests/api/health_test.rs
use reqwest;

#[tokio::test]
async fn test_health_live() {
    let client = reqwest::Client::new();
    let response = client
        .get("http://localhost:3000/health/live")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
}

#[tokio::test]
async fn test_health_ready_returns_db_status() {
    let client = reqwest::Client::new();
    let response = client
        .get("http://localhost:3000/health/ready")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body: serde_json::Value = response.json().await.unwrap();
    assert!(body["data"]["database"].is_string());
    assert!(body["data"]["redis"].is_string());
}
```

**Step 2: Implement health routes**

```rust
// backend/src/routes/health.rs
use axum::{extract::State, Json};
use crate::errors::ApiResponse;
use crate::AppState;
use serde::Serialize;

#[derive(Serialize)]
pub struct HealthStatus {
    pub status: String,
    pub database: String,
    pub redis: String,
}

pub async fn live() -> &'static str {
    "OK"
}

pub async fn ready(State(state): State<AppState>) -> Json<ApiResponse<HealthStatus>> {
    let db_status = match sqlx::query("SELECT 1").execute(&state.db).await {
        Ok(_) => "connected".to_string(),
        Err(e) => format!("error: {}", e),
    };

    let redis_status = match state.redis.get_async_connection().await {
        Ok(_) => "connected".to_string(),
        Err(e) => format!("error: {}", e),
    };

    ApiResponse::success(HealthStatus {
        status: "ok".to_string(),
        database: db_status,
        redis: redis_status,
    })
}
```

**Step 3: Wire up routes in main, run tests, commit**

```bash
cd backend && cargo test
git add backend/src/routes/
git commit -m "feat: add health check endpoints (/health/live, /health/ready)"
```

---

### Task 10: AppState and Application Bootstrap

**Files:**
- Modify: `backend/src/main.rs`
- Modify: `backend/src/lib.rs`

Set up the shared `AppState` struct containing the database pool, Redis connection, and config. Wire up the Axum router with all middleware (CORS, tracing, compression). This is the central application bootstrap that all subsequent routes plug into.

**Step 1: Define AppState**

```rust
// in backend/src/lib.rs
use sqlx::PgPool;

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub config: config::AppConfig,
    // Redis will be added when needed
}
```

**Step 2: Wire up main.rs with full router, CORS, tracing middleware**

Update `main.rs` to:
1. Create database pool
2. Run migrations on startup
3. Build Axum router with CORS, tower-http tracing, health routes
4. Start server

**Step 3: Verify server starts and health endpoints work**

Run: `cd backend && cargo run`
Then: `curl http://localhost:3000/health/live` → `OK`
And: `curl http://localhost:3000/health/ready` → JSON with db/redis status

**Step 4: Commit**

```bash
git add backend/src/
git commit -m "feat: add AppState, application bootstrap, and middleware stack"
```

---

### Task 11: Authentication — User Registration and Login

**Files:**
- Create: `backend/src/services/auth.rs`
- Create: `backend/src/routes/auth.rs`
- Create: `backend/src/middleware/auth.rs`
- Create: `backend/tests/api/auth_test.rs`

**Step 1: Write failing tests for registration and login**

Tests should cover:
- Register new user (admin-only operation)
- Login with valid credentials → returns JWT access + refresh tokens
- Login with invalid password → 401
- Login with locked account (3 failed attempts) → 401 with locked message
- Access protected endpoint without token → 401
- Access protected endpoint with valid token → 200
- Access endpoint with wrong role → 403

**Step 2: Implement auth service**

The auth service handles:
- Password hashing with argon2id
- User creation (admin-only)
- Login validation (password check, lockout check, failed attempt tracking)
- JWT generation (access token: 15 min, refresh token: 7 days)
- Token validation and refresh

**Step 3: Implement auth middleware**

Tower middleware that:
1. Extracts JWT from `Authorization: Bearer <token>` header
2. Validates token signature and expiry
3. Loads user from database
4. Injects `CurrentUser` into request extensions

**Step 4: Implement RBAC middleware**

```rust
// backend/src/middleware/rbac.rs
// Axum middleware/extractor that checks CurrentUser.role against required roles
pub fn require_role(allowed_roles: &[UserRole]) -> impl Fn(/* ... */) -> /* ... */
```

**Step 5: Wire up auth routes**

```
POST /api/v1/auth/login          → Login, returns tokens
POST /api/v1/auth/refresh        → Refresh access token
POST /api/v1/auth/logout         → Invalidate refresh token
POST /api/v1/auth/users          → Create user (Admin only)
GET  /api/v1/auth/me             → Get current user profile
```

**Step 6: Run tests, verify all pass**

Run: `cd backend && cargo test -- --test-threads=1`
(Sequential because auth tests share database state)

**Step 7: Commit**

```bash
git add backend/src/services/auth.rs backend/src/routes/auth.rs backend/src/middleware/ backend/tests/
git commit -m "feat: add authentication with argon2id, JWT, account lockout, RBAC"
```

---

## Section D: Application Registry API

### Task 12: Application CRUD Service and Routes

**Files:**
- Create: `backend/src/services/application.rs`
- Create: `backend/src/routes/applications.rs`
- Create: `backend/tests/api/applications_test.rs`
- Create: `backend/tests/fixtures/apm_sample.csv`

**Step 1: Write failing tests**

Tests:
- Create application with all required fields → 201
- Create application with duplicate app_code → 409 Conflict
- Get application by ID → 200
- Get application by app_code → 200
- List applications with pagination → 200 with page info
- Update application → 200
- Create stub application (is_verified = false) → 201
- List unverified applications → 200 (filtered)
- Import applications from JSON → 201 with count
- Import applications from corporate APM CSV → 201 with count (~5000 records)
- APM CSV import resolves Struttura Reale ownership override correctly
- APM CSV import sets criticality fallback to Medium when ACRONYM CRITICALITY is empty
- APM CSV import maps regulatory flags (DORA FEI, GDPR, PCI, PSD2)
- APM CSV import stores full record in apm_metadata JSONB
- APM CSV import is repeatable (update existing by app_code, insert new)
- Filter applications by regulatory flag (is_dora_fei, is_gdpr_subject, etc.)
- Filter applications by SSA code
- Only Platform_Admin and AppSec_Manager can create/update/import applications

**Step 2: Implement application service**

Key functions:
- `create(app: CreateApplication) -> Result<Application>`
- `find_by_id(id: Uuid) -> Result<Application>`
- `find_by_app_code(code: &str) -> Result<Option<Application>>`
- `find_or_create_stub(app_code: &str, source_tool: &str) -> Result<Application>`
- `list(filters: ApplicationFilters, pagination: Pagination) -> Result<PagedResult<Application>>`
- `update(id: Uuid, update: UpdateApplication) -> Result<Application>`
- `import_bulk(apps: Vec<CreateApplication>) -> Result<ImportResult>`
- `import_apm_csv(data: &[u8], field_mapping: &ApmFieldMapping) -> Result<ApmImportResult>`

The `import_apm_csv` function:
1. Parse CSV with configurable field mapping (CSV column name → SynApSec field)
2. For each row:
   a. Extract `app_code` from CODICE ACRONIMO column
   b. Map dedicated columns (SSA, CIA levels, regulatory flags, references)
   c. Apply Struttura Reale ownership override logic:
      - If STRUTTURA REALE DI GESTIONE fields populated AND differ from UFFICIO/SERVIZIO/DIREZIONE → use Struttura Reale's RESPONSABILE as effective_office_owner
      - Else → use RESPONSABILE UFFICIO as effective_office_owner
   d. Map criticality from ACRONYM CRITICALITY (SYNTHESIS LEVEL) to asset_criticality enum; default "Medium" if empty
   e. Store entire CSV row as JSON in apm_metadata
   f. Upsert by app_code (update if exists, insert if new)
3. Return summary: total, created, updated, skipped, errors

The `ApmFieldMapping` struct allows configurable CSV-to-field mapping:
```rust
pub struct ApmFieldMapping {
    pub app_code_column: String,           // default: "CODICE ACRONIMO"
    pub app_name_column: String,           // default: "DESCRIZIONE ACRONIMO"
    pub ssa_code_column: String,           // default: "CODICE SSA"
    pub criticality_column: String,        // default: "ACRONYM CRITICALITY (SYNTHESIS LEVEL)"
    pub functional_ref_email_column: String,
    pub technical_ref_email_column: String,
    pub office_owner_column: String,       // default: "RESPONSABILE UFFICIO NOMINATIVO"
    pub struttura_reale_owner_column: String, // default: "RESPONSABILE STRUTTURA REALE DI GESTIONE"
    // ... additional mappings as needed
}
```

Default mapping is provided; users can override via the import UI or API.

**Step 3: Implement routes**

```
GET    /api/v1/applications              → List (with filters, pagination)
POST   /api/v1/applications              → Create
GET    /api/v1/applications/:id          → Get by ID
PUT    /api/v1/applications/:id          → Update
GET    /api/v1/applications/code/:code   → Get by app_code
POST   /api/v1/applications/import       → Bulk import (JSON)
POST   /api/v1/applications/import/apm   → Corporate APM CSV/Excel import (multipart)
GET    /api/v1/applications/unverified   → List unverified stubs
```

**Step 4: Run tests, commit**

```bash
cd backend && cargo test
git add backend/src/services/application.rs backend/src/routes/applications.rs backend/tests/
git commit -m "feat: add application registry CRUD with APM import, ownership override, and bulk operations"
```

---

## Section E: Finding API

### Task 13: Finding CRUD Service

**Files:**
- Create: `backend/src/services/finding.rs`
- Create: `backend/src/routes/findings.rs`
- Create: `backend/tests/api/findings_test.rs`

**Step 1: Write failing tests**

Tests:
- Create finding with core fields → 201
- Create SAST finding with category-specific fields → 201 (inserts into both `findings` and `finding_sast`)
- Get finding by ID → 200 (includes category-specific fields)
- List findings with pagination → 200
- List findings with filters (severity, status, category, application_id) → 200
- Full-text search findings → 200 (matches title and description)
- Update finding status → 200
- Add comment to finding → 201
- Get finding history → 200

**Step 2: Implement finding service**

Key functions:
- `create(finding: CreateFinding, category_data: CategoryData) -> Result<Finding>`
- `find_by_id(id: Uuid) -> Result<FindingWithDetails>`
- `find_by_fingerprint(fingerprint: &str) -> Result<Option<Finding>>`
- `list(filters: FindingFilters, pagination: Pagination) -> Result<PagedResult<FindingSummary>>`
- `search(query: &str, filters: FindingFilters, pagination: Pagination) -> Result<PagedResult<FindingSummary>>`
- `update_status(id: Uuid, new_status: FindingStatus, actor: &User, justification: Option<String>) -> Result<Finding>`
- `add_comment(finding_id: Uuid, author: &User, content: String) -> Result<Comment>`
- `get_history(finding_id: Uuid) -> Result<Vec<HistoryEntry>>`

The `CategoryData` enum:
```rust
pub enum CategoryData {
    Sast(CreateFindingSast),
    Sca(CreateFindingSca),
    Dast(CreateFindingDast),
}
```

**Step 3: Implement routes**

```
GET    /api/v1/findings                  → List (filters, pagination, search)
POST   /api/v1/findings                  → Create
GET    /api/v1/findings/:id              → Get by ID (with category details)
PUT    /api/v1/findings/:id              → Update
PATCH  /api/v1/findings/:id/status       → Update status (with justification)
POST   /api/v1/findings/:id/comments     → Add comment
GET    /api/v1/findings/:id/comments     → List comments
GET    /api/v1/findings/:id/history      → Get history
POST   /api/v1/findings/bulk/status      → Bulk status update
POST   /api/v1/findings/bulk/assign      → Bulk assign
POST   /api/v1/findings/bulk/tag         → Bulk tag
```

**Step 4: Run tests, commit**

```bash
cd backend && cargo test
git add backend/src/services/finding.rs backend/src/routes/findings.rs backend/tests/
git commit -m "feat: add finding CRUD with category-specific layers, search, and history"
```

---

### Task 14: Fingerprint Computation Service

**Files:**
- Create: `backend/src/services/fingerprint.rs`
- Create: `backend/tests/services/fingerprint_test.rs`

**Step 1: Write failing tests**

```rust
#[test]
fn test_sast_fingerprint_excludes_line_number() {
    let fp1 = compute_sast_fingerprint("APP1", "src/main.rs", "sqli-rule", "main");
    let fp2 = compute_sast_fingerprint("APP1", "src/main.rs", "sqli-rule", "main");
    assert_eq!(fp1, fp2); // Same inputs → same fingerprint
}

#[test]
fn test_sast_fingerprint_different_file() {
    let fp1 = compute_sast_fingerprint("APP1", "src/main.rs", "sqli-rule", "main");
    let fp2 = compute_sast_fingerprint("APP1", "src/other.rs", "sqli-rule", "main");
    assert_ne!(fp1, fp2); // Different file → different fingerprint
}

#[test]
fn test_dast_fingerprint_excludes_cwe() {
    let fp1 = compute_dast_fingerprint("APP1", "/api/login", "POST", "username");
    let fp2 = compute_dast_fingerprint("APP1", "/api/login", "POST", "username");
    assert_eq!(fp1, fp2);
}

#[test]
fn test_sca_fingerprint_includes_cve() {
    let fp1 = compute_sca_fingerprint("APP1", "lodash", "4.17.20", "CVE-2021-23337");
    let fp2 = compute_sca_fingerprint("APP1", "lodash", "4.17.20", "CVE-2021-99999");
    assert_ne!(fp1, fp2); // Different CVE → different fingerprint
}
```

**Step 2: Implement fingerprint service**

```rust
// backend/src/services/fingerprint.rs
use sha2::{Sha256, Digest};
use hex;

pub fn compute_sast_fingerprint(app_code: &str, file_path: &str, rule_id: &str, branch: &str) -> String {
    let input = format!("SAST:{}:{}:{}:{}", app_code, file_path, rule_id, branch);
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

pub fn compute_sca_fingerprint(app_code: &str, package_name: &str, package_version: &str, cve_id: &str) -> String {
    let input = format!("SCA:{}:{}:{}:{}", app_code, package_name, package_version, cve_id);
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

pub fn compute_dast_fingerprint(app_code: &str, target_url: &str, http_method: &str, parameter: &str) -> String {
    let input = format!("DAST:{}:{}:{}:{}", app_code, target_url, http_method, parameter);
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}
```

**Step 3: Run tests, commit**

```bash
cd backend && cargo test
git add backend/src/services/fingerprint.rs backend/tests/
git commit -m "feat: add fingerprint computation for SAST, SCA, DAST categories"
```

---

### Task 15: Risk Score Computation Service

**Files:**
- Create: `backend/src/services/risk_score.rs`
- Create: `backend/tests/services/risk_score_test.rs`

**Step 1: Write failing tests**

Test the composite risk score calculation with the 5 factors. Test cases from the PRD (Appendix E example), plus edge cases (Info severity, no application context, standalone finding).

**Step 2: Implement risk score service**

The service:
1. Loads weights from system_config (cached in Redis)
2. Computes each factor score
3. Calculates weighted sum
4. Returns composite score (0-100) and priority level (P1-P5)

Finding Age factor is computed dynamically based on current time vs. `status_changed_at` (when finding entered Confirmed) relative to SLA.

Correlation Density requires counting related findings from `finding_relationships` table.

**Step 3: Run tests, commit**

```bash
cd backend && cargo test
git add backend/src/services/risk_score.rs backend/tests/
git commit -m "feat: add composite risk score computation with 5-factor model"
```

---

## Section F: Ingestion Framework

### Task 16: Parser Trait Definition

**Files:**
- Create: `backend/src/parsers/mod.rs`

**Step 1: Define the Parser trait**

```rust
// backend/src/parsers/mod.rs
pub mod sonarqube;
pub mod sarif;

use crate::models::finding::{CreateFinding, FindingCategory};
use crate::services::finding::CategoryData;

#[derive(Debug)]
pub struct ParsedFinding {
    pub core: CreateFinding,
    pub category_data: CategoryData,
}

#[derive(Debug)]
pub struct ParseResult {
    pub findings: Vec<ParsedFinding>,
    pub errors: Vec<ParseError>,
    pub source_tool: String,
    pub source_tool_version: Option<String>,
}

#[derive(Debug)]
pub struct ParseError {
    pub record_index: usize,
    pub field: String,
    pub message: String,
}

pub trait Parser: Send + Sync {
    /// Parse raw scanner output into normalized findings
    fn parse(&self, data: &[u8], format: InputFormat) -> Result<ParseResult, anyhow::Error>;

    /// The scanner tool name this parser handles
    fn source_tool(&self) -> &str;

    /// The finding category this parser produces
    fn category(&self) -> FindingCategory;

    /// Severity mapping from tool-specific to normalized
    fn map_severity(&self, tool_severity: &str) -> SeverityLevel;
}

#[derive(Debug, Clone)]
pub enum InputFormat {
    Json,
    Csv,
    Xml,
    Sarif,
}
```

**Step 2: Commit**

```bash
git add backend/src/parsers/mod.rs
git commit -m "feat: define Parser trait for pluggable scanner integrations"
```

---

### Task 17: SonarQube Parser Implementation

**Files:**
- Create: `backend/src/parsers/sonarqube.rs`
- Create: `backend/tests/parsers/sonarqube_test.rs`
- Create: `backend/tests/fixtures/sonarqube_sample.json`
- Create: `backend/tests/fixtures/sonarqube_sample.csv`

**Step 1: Create test fixture files**

Create realistic sample SonarQube output files (JSON and CSV) with the fields the user described: application_code, project_key, rule_key, issue_id, rule_name, tag, issue_description, severity, issue_type, loc, component, branch, url, creation_date, quality_gate, baseline_date, last_analysis, extraction_date, rule_type.

Include 5-10 sample findings covering: different severities (BLOCKER through INFO), both VULNERABILITY and SECURITY_HOTSPOT issue types, multiple application codes.

**Step 2: Write failing tests**

```rust
#[test]
fn test_parse_sonarqube_json() {
    let parser = SonarQubeParser::new();
    let data = include_bytes!("../fixtures/sonarqube_sample.json");
    let result = parser.parse(data, InputFormat::Json).unwrap();
    assert_eq!(result.findings.len(), 10);
    assert_eq!(result.source_tool, "SonarQube");
}

#[test]
fn test_sonarqube_severity_mapping() {
    let parser = SonarQubeParser::new();
    assert_eq!(parser.map_severity("BLOCKER"), SeverityLevel::Critical);
    assert_eq!(parser.map_severity("CRITICAL"), SeverityLevel::High);
    assert_eq!(parser.map_severity("MAJOR"), SeverityLevel::Medium);
    assert_eq!(parser.map_severity("MINOR"), SeverityLevel::Low);
    assert_eq!(parser.map_severity("INFO"), SeverityLevel::Info);
}

#[test]
fn test_sonarqube_extracts_app_code() {
    let parser = SonarQubeParser::new();
    let data = include_bytes!("../fixtures/sonarqube_sample.json");
    let result = parser.parse(data, InputFormat::Json).unwrap();
    // Verify app_code is extracted and set in metadata
    let first = &result.findings[0];
    assert!(first.core.metadata["app_code"].is_string());
}

#[test]
fn test_sonarqube_fingerprint_computed() {
    let parser = SonarQubeParser::new();
    let data = include_bytes!("../fixtures/sonarqube_sample.json");
    let result = parser.parse(data, InputFormat::Json).unwrap();
    let first = &result.findings[0];
    assert!(!first.core.fingerprint.is_empty());
}

#[test]
fn test_parse_sonarqube_csv() {
    let parser = SonarQubeParser::new();
    let data = include_bytes!("../fixtures/sonarqube_sample.csv");
    let result = parser.parse(data, InputFormat::Csv).unwrap();
    assert!(result.findings.len() > 0);
}
```

**Step 3: Implement SonarQube parser**

The parser:
1. Reads JSON or CSV format
2. Maps SonarQube fields to core + SAST-specific data model
3. Maps severity (BLOCKER→Critical, CRITICAL→High, MAJOR→Medium, MINOR→Low, INFO→Info)
4. Extracts `application_code` into metadata for application resolution
5. Computes SAST fingerprint: `Hash(app_code + file_path + rule_id + branch)`
6. Preserves original raw finding as JSON
7. Handles both VULNERABILITY and SECURITY_HOTSPOT issue types
8. Reports parsing errors per record (quarantine, don't fail)

**Step 4: Run tests, commit**

```bash
cd backend && cargo test
git add backend/src/parsers/sonarqube.rs backend/tests/
git commit -m "feat: add SonarQube parser with JSON/CSV support and severity mapping"
```

---

### Task 18: SARIF Parser Implementation

**Files:**
- Create: `backend/src/parsers/sarif.rs`
- Create: `backend/tests/parsers/sarif_test.rs`
- Create: `backend/tests/fixtures/sarif_sample.json`

Follow the same TDD pattern as Task 17. The SARIF parser handles the standard SARIF 2.1.0 format, mapping SARIF results to the SAST data model. SARIF is a standard format, so this parser enables any SARIF-compliant tool to integrate without a custom parser.

**Step 1-4:** Fixture, failing tests, implementation, verify, commit.

```bash
git commit -m "feat: add SARIF parser for generic SAST tool integration"
```

---

### Task 19: Ingestion Pipeline Service

**Files:**
- Create: `backend/src/services/ingestion.rs`
- Create: `backend/src/routes/ingestion.rs`
- Create: `backend/tests/api/ingestion_test.rs`

**Step 1: Write failing tests**

Tests:
- Upload SonarQube JSON file → 200, returns ingestion summary (N new, M updated, P duplicates, Q errors)
- Upload SARIF file → 200, returns ingestion summary
- Upload invalid file → 200 with errors reported (not 500 — graceful)
- Upload CSV file → 200
- Get ingestion history → 200, list of past ingestion events
- Get ingestion log details → 200, including error details
- Ingestion creates audit log entry
- Findings with known app_code get application_id resolved
- Findings with unknown app_code create stub applications

**Step 2: Implement ingestion service**

The ingestion service orchestrates the 9-stage pipeline:

```rust
pub async fn ingest_file(
    db: &PgPool,
    file_data: &[u8],
    file_name: &str,
    format: InputFormat,
    parser_type: &str,
    initiated_by: &User,
) -> Result<IngestionResult> {
    // 1. Select parser based on parser_type
    // 2. Parse raw data → Vec<ParsedFinding>
    // 3. For each parsed finding:
    //    a. Resolve application (app_code lookup → stub creation)
    //    b. Compute fingerprint (if not already computed by parser)
    //    c. Check deduplication (find existing by fingerprint)
    //    d. If duplicate: update last_seen, skip creation
    //    e. If new: insert finding + category data
    //    f. Apply auto-confirm logic (check triage rules)
    //    g. Compute initial risk score
    // 4. Log ingestion event
    // 5. Return summary
}
```

**Step 3: Implement ingestion route**

```
POST /api/v1/ingestion/upload     → File upload (multipart form)
     Parameters: file, parser_type (sonarqube|sarif), format (json|csv|xml|sarif)
GET  /api/v1/ingestion/history    → List past ingestion events
GET  /api/v1/ingestion/:id        → Get ingestion log details
```

**Step 4: Run tests, commit**

```bash
cd backend && cargo test
git add backend/src/services/ingestion.rs backend/src/routes/ingestion.rs backend/tests/
git commit -m "feat: add ingestion pipeline with file upload, app resolution, and dedup"
```

---

## Section G: Deduplication

### Task 20: Deduplication Service

**Files:**
- Create: `backend/src/services/deduplication.rs`
- Create: `backend/tests/services/deduplication_test.rs`

**Step 1: Write failing tests**

```rust
#[test]
fn test_intra_tool_dedup_same_fingerprint() {
    // Two findings with same fingerprint from same tool
    // → second should update last_seen on first, not create new
}

#[test]
fn test_intra_tool_dedup_different_fingerprint() {
    // Two findings with different fingerprints
    // → both should be created as separate findings
}

#[test]
fn test_dedup_updates_last_seen() {
    // When a duplicate is found, last_seen must update to current time
}

#[test]
fn test_dedup_preserves_status() {
    // A duplicate match must NOT reset the status of an existing finding
}

#[test]
fn test_dedup_reopen_closed_finding() {
    // If a Closed finding's fingerprint reappears → re-open as New
}

#[test]
fn test_dedup_audit_logged() {
    // Every dedup decision must create an audit entry
}
```

**Step 2: Implement deduplication service**

```rust
pub enum DedupResult {
    New,                          // No match — create new finding
    Updated(Uuid),                // Match found — updated last_seen
    Reopened(Uuid),               // Match found but was Closed — reopened
}

pub async fn check_and_apply(
    db: &PgPool,
    parsed: &ParsedFinding,
) -> Result<DedupResult> {
    // 1. Query findings by fingerprint
    // 2. If no match → DedupResult::New
    // 3. If match found:
    //    a. If match.status == Closed → reopen (set status = New, update last_seen)
    //    b. Else → update last_seen only
    // 4. Log dedup decision in finding_history
}
```

**Step 3: Run tests, commit**

```bash
cd backend && cargo test
git add backend/src/services/deduplication.rs backend/tests/
git commit -m "feat: add intra-tool deduplication with reopening logic"
```

---

## Section H: Lifecycle Management

### Task 21: State Machine Implementation

**Files:**
- Create: `backend/src/services/lifecycle.rs`
- Create: `backend/tests/services/lifecycle_test.rs`

**Step 1: Write comprehensive failing tests**

Tests for every valid and invalid transition:

```rust
#[test]
fn test_new_to_confirmed_auto() { /* auto-confirm */ }
#[test]
fn test_confirmed_to_in_remediation() { /* analyst assigns */ }
#[test]
fn test_confirmed_to_false_positive() { /* analyst marks FP */ }
#[test]
fn test_confirmed_to_false_positive_requested() { /* developer disputes */ }
#[test]
fn test_fp_requested_to_false_positive() { /* analyst approves dispute */ }
#[test]
fn test_fp_requested_to_confirmed() { /* analyst rejects dispute */ }
#[test]
fn test_confirmed_to_risk_accepted() { /* requires manager approval */ }
#[test]
fn test_confirmed_to_deferred_remediation() { /* requires committed date */ }
#[test]
fn test_in_remediation_to_mitigated() { /* developer marks fixed */ }
#[test]
fn test_mitigated_to_verified() { /* analyst verifies */ }
#[test]
fn test_verified_to_closed() { /* auto or analyst */ }
#[test]
fn test_closed_to_new_on_redetection() { /* auto reopen */ }
#[test]
fn test_risk_accepted_expires_to_confirmed() { /* auto on expiry */ }
#[test]
fn test_any_to_invalidated_admin_only() { /* admin can invalidate */ }

// Invalid transitions
#[test]
fn test_new_to_closed_invalid() { /* cannot skip states */ }
#[test]
fn test_developer_cannot_mark_false_positive() { /* RBAC enforced */ }
#[test]
fn test_risk_accepted_requires_justification() { /* missing justification → error */ }
#[test]
fn test_bulk_excludes_risk_accepted() { /* bulk cannot transition to Risk_Accepted */ }
```

**Step 2: Implement lifecycle service**

```rust
pub struct TransitionRequest {
    pub finding_id: Uuid,
    pub new_status: FindingStatus,
    pub actor: User,
    pub justification: Option<String>,
    pub committed_date: Option<DateTime<Utc>>,  // For Deferred_Remediation
    pub expiry_date: Option<DateTime<Utc>>,     // For Risk_Accepted
}

pub async fn transition(
    db: &PgPool,
    request: TransitionRequest,
) -> Result<Finding, AppError> {
    // 1. Load current finding
    // 2. Validate transition is allowed (from → to)
    // 3. Validate actor has required role for this transition
    // 4. Validate required fields (justification, dates)
    // 5. Apply transition
    // 6. Compute SLA if entering Confirmed
    // 7. Log to finding_history
    // 8. Log to audit_log
    // 9. Return updated finding
}

fn is_valid_transition(from: &FindingStatus, to: &FindingStatus) -> bool {
    matches!(
        (from, to),
        (FindingStatus::New, FindingStatus::Confirmed)
            | (FindingStatus::Confirmed, FindingStatus::InRemediation)
            | (FindingStatus::Confirmed, FindingStatus::FalsePositive)
            | (FindingStatus::Confirmed, FindingStatus::FalsePositiveRequested)
            | (FindingStatus::FalsePositiveRequested, FindingStatus::FalsePositive)
            | (FindingStatus::FalsePositiveRequested, FindingStatus::Confirmed)
            | (FindingStatus::Confirmed, FindingStatus::RiskAccepted)
            | (FindingStatus::Confirmed, FindingStatus::DeferredRemediation)
            | (FindingStatus::DeferredRemediation, FindingStatus::InRemediation)
            | (FindingStatus::InRemediation, FindingStatus::Mitigated)
            | (FindingStatus::Mitigated, FindingStatus::Verified)
            | (FindingStatus::Verified, FindingStatus::Closed)
            | (FindingStatus::RiskAccepted, FindingStatus::Confirmed)
            | (FindingStatus::Closed, FindingStatus::New)
            // Invalidated can come from any state (admin only)
            | (_, FindingStatus::Invalidated)
    )
}

fn required_role(to: &FindingStatus) -> Vec<UserRole> {
    match to {
        FindingStatus::RiskAccepted => vec![UserRole::AppSecManager, UserRole::PlatformAdmin],
        FindingStatus::DeferredRemediation => vec![UserRole::AppSecManager, UserRole::PlatformAdmin],
        FindingStatus::Invalidated => vec![UserRole::PlatformAdmin],
        FindingStatus::FalsePositiveRequested => vec![UserRole::Developer, UserRole::AppSecAnalyst, UserRole::AppSecManager, UserRole::PlatformAdmin],
        FindingStatus::Mitigated => vec![UserRole::Developer, UserRole::AppSecAnalyst, UserRole::AppSecManager, UserRole::PlatformAdmin],
        _ => vec![UserRole::AppSecAnalyst, UserRole::AppSecManager, UserRole::PlatformAdmin],
    }
}
```

**Step 3: Implement triage rules engine**

```rust
pub async fn should_hold_for_triage(
    db: &PgPool,
    finding: &CreateFinding,
    application: Option<&Application>,
) -> Result<bool> {
    // Load active triage rules from triage_rules table
    // Evaluate each rule's conditions against finding + application
    // If any rule matches → return true (hold in New)
    // Default → return false (auto-confirm)
}
```

**Step 4: Run tests, commit**

```bash
cd backend && cargo test
git add backend/src/services/lifecycle.rs backend/tests/
git commit -m "feat: add finding lifecycle state machine with RBAC and triage rules"
```

---

## Section I: Frontend

### Task 22: Application Shell — Layout, Routing, Theme

**Files:**
- Create: `frontend/src/App.tsx`
- Create: `frontend/src/components/layout/AppLayout.tsx`
- Create: `frontend/src/components/layout/Sidebar.tsx`
- Create: `frontend/src/components/layout/Header.tsx`
- Create: `frontend/src/components/layout/ThemeToggle.tsx`
- Create: `frontend/src/stores/authStore.ts`
- Modify: `frontend/src/main.tsx`

Build the application shell:
- Sidebar navigation with all page links
- Header with user info, language toggle, theme toggle
- Dark/light theme using CSS variables
- TanStack Router setup with all routes defined
- Auth store (tracks current user, JWT tokens)
- Protected route wrapper (redirects to login if unauthenticated)
- Custom font integration (select a modern, professional font — e.g., Inter)
- Responsive layout

**Step 1: Set up routing**

Define all routes:
```
/login                → LoginPage
/                     → DashboardPage (redirect if not authed)
/findings             → FindingsPage
/findings/:id         → FindingDetailPage
/applications         → ApplicationsPage
/applications/:id     → ApplicationDetailPage
/ingestion            → IngestionPage
/triage               → TriageQueuePage
/unmapped             → UnmappedAppsPage
```

**Step 2: Build layout components**

Professional sidebar with navigation groups, active state highlighting, collapse capability. Header with breadcrumbs, user avatar, language switch, theme toggle.

**Step 3: Implement theme toggle**

Light/dark mode using TailwindCSS `dark:` classes and CSS variables for shadcn/ui theming.

**Step 4: Verify in browser, commit**

```bash
git add frontend/src/
git commit -m "feat: add application shell with sidebar, routing, theme toggle, i18n"
```

---

### Task 23: Login Page

**Files:**
- Create: `frontend/src/pages/LoginPage.tsx`
- Create: `frontend/src/components/auth/LoginForm.tsx`
- Create: `frontend/src/api/client.ts`
- Create: `frontend/src/api/auth.ts`

Build the login page:
- Clean, modern login form (username + password)
- Form validation (client-side)
- API call to POST `/api/v1/auth/login`
- Store JWT tokens on success
- Display error message on failure (invalid credentials, locked account)
- Redirect to dashboard on success
- Fully i18n-ized

**Step 1-3:** Component, API client, wire up, test manually.

**Step 4: Commit**

```bash
git add frontend/src/
git commit -m "feat: add login page with authentication flow"
```

---

### Task 24: API Client Setup

**Files:**
- Create: `frontend/src/api/client.ts`
- Create: `frontend/src/types/api.ts`

Build a typed fetch wrapper:
- Automatically adds JWT Bearer token from auth store
- Handles token refresh on 401
- Parses `ApiResponse<T>` envelope
- Throws typed errors
- Base URL configuration

```typescript
// frontend/src/api/client.ts
const API_BASE = '/api/v1';

export async function apiGet<T>(path: string, params?: Record<string, string>): Promise<T> { ... }
export async function apiPost<T>(path: string, body: unknown): Promise<T> { ... }
export async function apiPut<T>(path: string, body: unknown): Promise<T> { ... }
export async function apiPatch<T>(path: string, body: unknown): Promise<T> { ... }
export async function apiUpload<T>(path: string, formData: FormData): Promise<T> { ... }
```

**Commit:**

```bash
git commit -m "feat: add typed API client with auth token management"
```

---

### Task 25: Findings List Page

**Files:**
- Create: `frontend/src/pages/FindingsPage.tsx`
- Create: `frontend/src/components/findings/FindingList.tsx`
- Create: `frontend/src/components/findings/FindingFilters.tsx`
- Create: `frontend/src/components/findings/FindingStatusBadge.tsx`
- Create: `frontend/src/api/findings.ts`
- Create: `frontend/src/types/finding.ts`
- Create: `frontend/src/hooks/useFindings.ts`

Build the primary findings view:
- TanStack Table with sortable columns (title, severity, status, application, source tool, first seen, risk score)
- Color-coded severity and status badges
- Filter panel (severity, status, category, application, date range)
- Full-text search bar
- Pagination
- Row click navigates to finding detail
- Bulk select with bulk action bar (assign, tag, status change — respecting governance rules)
- i18n for all labels

**Commit:**

```bash
git commit -m "feat: add findings list page with filters, search, and pagination"
```

---

### Task 26: Finding Detail Page

**Files:**
- Create: `frontend/src/pages/FindingDetailPage.tsx`
- Create: `frontend/src/components/findings/FindingDetail.tsx`
- Create: `frontend/src/components/findings/FindingTransitionDialog.tsx`

Build the finding detail view:
- Core finding information (title, description, severity, risk score, status)
- Category-specific fields displayed in appropriate sections (SAST: file, line, code snippet; SCA: package, CVE, fixed version; DAST: URL, method, evidence)
- Status transition controls (buttons for valid next states based on current status + user role)
- Transition dialog with justification field (required for governed transitions)
- Committed date picker for Deferred_Remediation
- Expiry date picker for Risk_Accepted
- Comment thread
- History timeline (all state changes, comments, assignments)
- Raw finding viewer (collapsible JSON view)
- Application link
- Related findings / relationships (links to duplicates, correlations)

**Commit:**

```bash
git commit -m "feat: add finding detail page with status transitions and comments"
```

---

### Task 27: Applications Pages

**Files:**
- Create: `frontend/src/pages/ApplicationsPage.tsx`
- Create: `frontend/src/pages/ApplicationDetailPage.tsx`
- Create: `frontend/src/components/applications/ApplicationList.tsx`
- Create: `frontend/src/components/applications/ApplicationDetail.tsx`
- Create: `frontend/src/components/applications/ApplicationForm.tsx`
- Create: `frontend/src/api/applications.ts`
- Create: `frontend/src/types/application.ts`

Build application registry views:
- List page with search and filters (criticality, status, business unit)
- Detail page showing: metadata, finding summary counts by severity/status, scanner project mappings
- Create/edit form (admin/manager only)
- JSON import for bulk application loading

**Commit:**

```bash
git commit -m "feat: add application registry pages with CRUD and bulk import"
```

---

### Task 28: Ingestion Page

**Files:**
- Create: `frontend/src/pages/IngestionPage.tsx`
- Create: `frontend/src/components/ingestion/FileUpload.tsx`
- Create: `frontend/src/components/ingestion/IngestionHistory.tsx`
- Create: `frontend/src/api/ingestion.ts`

Build the ingestion interface:
- File upload area (drag-and-drop)
- Parser type selection (SonarQube, SARIF)
- Format selection (JSON, CSV)
- Upload progress indicator
- Ingestion result summary (new, updated, duplicates, errors, quarantined)
- Ingestion history table (past imports with status, counts, timestamps)
- Error detail viewer for failed imports

**Commit:**

```bash
git commit -m "feat: add ingestion page with file upload and history"
```

---

### Task 29: Triage Queue and Unmapped Apps Pages

**Files:**
- Create: `frontend/src/pages/TriageQueuePage.tsx`
- Create: `frontend/src/pages/UnmappedAppsPage.tsx`

**Triage Queue:**
- List of findings held in "New" status by triage rules
- Quick-action buttons: Confirm, Mark False Positive
- Sortable by risk score, severity, first seen
- Context about why the finding was held (which triage rule matched)

**Unmapped Apps:**
- List of auto-created stub applications (is_verified = false)
- For each: source scanner project, number of findings associated
- Actions: verify (mark as real application), merge with existing application, edit details

**Commit:**

```bash
git commit -m "feat: add triage queue and unmapped applications pages"
```

---

### Task 30: Basic Dashboard Page

**Files:**
- Create: `frontend/src/pages/DashboardPage.tsx`

Build a basic operational dashboard:
- Findings requiring triage count (New status)
- Open findings by severity (card/badge counts)
- Recent ingestion activity (last 5 imports)
- Unmapped applications count
- SLA status summary (on-track, at-risk, breached counts)
- Top 5 riskiest applications

This is a basic version — the full dashboards with charts and trend analysis are Phase 2-3.

**Commit:**

```bash
git commit -m "feat: add basic operational dashboard"
```

---

## Section J: Integration Testing and Polish

### Task 31: End-to-End Integration Test

**Files:**
- Create: `backend/tests/integration/full_pipeline_test.rs`

Write one comprehensive integration test that exercises the full Phase 1 pipeline:

1. Create admin user
2. Login → get JWT
3. Create an application (app_code: "PAYM1")
4. Upload a SonarQube JSON file via ingestion endpoint
5. Verify findings were created
6. Verify application_id was resolved
7. Verify deduplication (upload same file again, verify no new findings, last_seen updated)
8. Verify finding status is Confirmed (auto-confirm)
9. Transition a finding to In_Remediation
10. Add a comment
11. Verify finding history has entries
12. Search for findings by text
13. Filter findings by severity
14. Verify ingestion history shows both imports

**Commit:**

```bash
git commit -m "test: add full pipeline integration test for Phase 1"
```

---

### Task 32: Seed Data Script

**Files:**
- Create: `backend/src/seed.rs` (or `docker/scripts/seed.sh`)

Create a seed script that populates the dev database with:
- Default admin user (admin / change-me-immediately)
- 5 sample applications with varying criticality tiers
- Sample SonarQube findings (imported via the ingestion pipeline)
- Sample triage rules

This makes it easy to start the platform and immediately see data.

**Commit:**

```bash
git commit -m "chore: add seed data script for development"
```

---

### Task 33: Final Cleanup and Documentation

**Step 1:** Run full test suite: `make test`
**Step 2:** Run linters: `make lint`
**Step 3:** Verify Docker Compose full stack: `make dev`
**Step 4:** Update CLAUDE.md files if any conventions changed during implementation
**Step 5:** Verify all Phase 1 exit criteria:
- [ ] SonarQube findings ingested via file import
- [ ] Findings deduplicated (intra-tool)
- [ ] Findings browsable in UI with search and filters
- [ ] Finding detail with category-specific fields
- [ ] Status transitions with governance rules
- [ ] Application registry with app_code resolution
- [ ] RBAC enforced (7 roles)
- [ ] Health check endpoints operational
- [ ] Structured JSON logging
- [ ] HTTPS everywhere
- [ ] i18n working (EN/IT)
- [ ] Light/dark theme

**Commit:**

```bash
git add -A
git commit -m "chore: Phase 1 cleanup — all exit criteria verified"
```

---

## Phases 2-4: High-Level Outline

These phases will receive detailed implementation plans as Phase 1 completes.

### Phase 2: Multi-Scanner & Correlation (Months 5-8)

**Task groups:**
- JFrog Xray parser (SCA) — same TDD pattern as SonarQube parser
- Tenable WAS parser (DAST) — same pattern
- Cross-tool deduplication service extension
- Correlation engine (rule-based, configurable, confidence model)
- Correlation graph visualization (React Flow or D3.js)
- Risk score: all 5 factors fully operational
- SLA framework with configurable tier mapping
- Notification engine (Email + Microsoft Teams adaptive cards)
- Automated assignment rules engine
- Rule-based smart triage (AI provider abstraction)
- False positive dispute workflow (UI)
- Application metrics + Prometheus/Grafana setup
- MFA via TOTP

### Phase 3: Governance & Reporting (Months 9-12)

**Task groups:**
- Executive dashboard (charts: Recharts/Nivo)
- Application risk view
- Compliance reports (PDF generation)
- Risk_Accepted full workflow (governance, approval chain, expiry)
- Deferred_Remediation tracking (committed dates, extended SLA)
- Non-conformity register
- Audit trail export
- SBOM module (import, storage, analysis — sbom-tools reference)
- Remediation guidance templates (CWE-based, EN/IT)
- Advanced correlation rules
- Custom report builder
- Trend analysis (time-series charts)
- Scheduled reports (cron/async jobs)
- Historical data bulk import
- Enterprise IdP (SAML 2.0 / OIDC)

### Phase 4: Maturation & Expansion (Months 13+)

**Task groups:**
- ServiceNow connector (bidirectional)
- Jira connector (bidirectional)
- Parser developer guide
- Performance optimization (query analysis, caching, indexing)
- Local LLM exploration (Ollama integration)
- Advanced automation rules (if-then engine)
- Expanded RBAC for VulnMgmt/SOC
- Kubernetes deployment manifests
- Data retention engine
- SBOM diffing and compliance validation

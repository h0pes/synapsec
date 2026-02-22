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

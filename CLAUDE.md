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

## Database Conventions
- **Role:** `synapsec_user` — dedicated PostgreSQL role for the application
- **Databases:** `synapsec_dev` (development), `synapsec_test` (integration tests), `synapsec_prod` (production)
- **Extensions:** `uuid-ossp` and `pgcrypto` installed on all databases
- **Migrations:** Managed by SQLx (`backend/migrations/`), applied automatically on server start
- **Local dev** connects to `synapsec_dev`; integration tests connect to `synapsec_test`
- Docker Compose provides PostgreSQL for containerized setups; local PostgreSQL works directly

## Development Commands
- `make dev` — Start all services (Docker Compose)
- `make test` — Run all tests (backend + frontend)
- `make test-backend` — Run Rust tests only
- `make test-frontend` — Run frontend tests only
- `make test-integration` — Run integration tests (requires `TEST_DATABASE_URL`)
- `make lint` — Run linters (clippy + eslint)
- `make migrate` — Run database migrations
- `make seed` — Seed development database with sample data
- `make setup-certs` — Generate mkcert certificates

## Coding Conventions

### Rust (Backend) — follows [Microsoft Pragmatic Rust Guidelines](https://microsoft.github.io/rust-guidelines/)
- All code must pass `cargo clippy` with no warnings (M-STATIC-VERIFICATION)
- Use `#[expect(lint)]` with reason instead of `#[allow(lint)]` (M-LINT-OVERRIDE-EXPECT)
- Use `thiserror` for domain error types as canonical structs (M-ERRORS-CANONICAL-STRUCTS), `anyhow` only in main/tests (M-APP-ERROR)
- All public types derive `Debug` (M-PUBLIC-DEBUG); error types also implement `Display` (M-PUBLIC-DISPLAY)
- All public API types derive `Serialize`, `Deserialize`
- Use `mimalloc` as global allocator (M-MIMALLOC-APP)
- Database queries use SQLx compile-time checked queries where possible
- All endpoints return consistent JSON envelope: `{ "data": ..., "error": null }`
- Error responses: `{ "data": null, "error": { "code": "...", "message": "..." } }`
- Structured logging via `tracing` with named fields, not string interpolation (M-LOG-STRUCTURED)
- Never log sensitive data (passwords, API keys, finding details in error messages)
- All timestamps in UTC, stored as `timestamptz` in PostgreSQL
- UUIDs for all primary keys (v7 for time-ordered, v4 for random)
- Panic only for programming bugs, never for request errors (M-PANIC-IS-STOP, M-PANIC-ON-BUG)
- Avoid `unsafe` unless justified with documented reason (M-UNSAFE)
- Name types descriptively — avoid "Service", "Manager", "Factory" (M-CONCISE-NAMES)
- Prefer concrete types > generics > `dyn Trait` (M-DI-HIERARCHY)
- Document all magic values and constants with rationale (M-DOCUMENTED-MAGIC)
- Long-running async tasks must yield cooperatively (M-YIELD-POINTS)
- See `backend/CLAUDE.md` for full guideline reference

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

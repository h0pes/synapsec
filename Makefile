.PHONY: dev dev-down test test-backend test-frontend test-integration lint migrate seed setup-certs

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

# Integration tests (requires TEST_DATABASE_URL)
test-integration:
	cd backend && cargo test --test full_pipeline_test -- --ignored

# Seed development database
seed:
	cd backend && cargo run --bin seed

# Certificates
setup-certs:
	./docker/scripts/setup-certs.sh

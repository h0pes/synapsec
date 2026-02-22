-- Extensions for the primary (dev) database (created by POSTGRES_DB env var)
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Create the test database for integration tests
CREATE DATABASE synapsec_test OWNER synapsec_user;
\c synapsec_test
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- The application will manage its own schema via SQLx migrations.
-- This file only handles extensions and the test database.

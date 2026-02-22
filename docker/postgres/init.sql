-- Create extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- The application will manage its own schema via SQLx migrations.
-- This file only handles extensions that require superuser privileges.

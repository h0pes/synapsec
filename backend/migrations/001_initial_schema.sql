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

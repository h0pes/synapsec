-- Phase 2: Correlation rules + app code patterns

-- ============================================================
-- CORRELATION RULES TABLE
-- ============================================================

CREATE TABLE correlation_rules (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        VARCHAR(255) NOT NULL,
    description TEXT,
    rule_type   VARCHAR(50) NOT NULL,
    conditions  JSONB NOT NULL,
    confidence  confidence_level NOT NULL DEFAULT 'Medium',
    is_active   BOOLEAN NOT NULL DEFAULT true,
    priority    INTEGER NOT NULL DEFAULT 0,
    created_by  UUID REFERENCES users(id),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TRIGGER update_correlation_rules_updated_at
    BEFORE UPDATE ON correlation_rules
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE INDEX idx_correlation_rules_active ON correlation_rules(is_active) WHERE is_active;
CREATE INDEX idx_correlation_rules_type ON correlation_rules(rule_type);

-- ============================================================
-- APP CODE PATTERNS TABLE
-- ============================================================

CREATE TABLE app_code_patterns (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_tool     VARCHAR(100) NOT NULL,
    field_name      VARCHAR(100) NOT NULL,
    regex_pattern   TEXT NOT NULL,
    priority        INTEGER NOT NULL DEFAULT 0,
    description     TEXT,
    is_active       BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TRIGGER update_app_code_patterns_updated_at
    BEFORE UPDATE ON app_code_patterns
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE INDEX idx_app_code_patterns_source_tool ON app_code_patterns(source_tool);
CREATE INDEX idx_app_code_patterns_active ON app_code_patterns(is_active) WHERE is_active;

-- ============================================================
-- SEED: DEFAULT CORRELATION RULES (CR-1 through CR-6)
-- ============================================================

INSERT INTO correlation_rules (name, description, rule_type, conditions, confidence, priority) VALUES
(
    'CR-1: Same CVE cross-category (SCA↔DAST)',
    'SCA reports vulnerable dependency; DAST confirms it is exploitable at a reachable endpoint. Both reference the same CVE.',
    'cross_tool',
    '{"match_on": "cve_id", "categories": ["SCA", "DAST"], "same_application": true}'::JSONB,
    'High',
    10
),
(
    'CR-2: Same CWE cross-category (SAST↔DAST)',
    'SAST finds code weakness; DAST confirms exploitability at an endpoint. Uses production-branch SAST findings.',
    'cross_tool',
    '{"match_on": "cwe_id", "categories": ["SAST", "DAST"], "same_application": true, "sast_branch": "production"}'::JSONB,
    'Medium',
    9
),
(
    'CR-3: SCA vulnerable package matched to SAST file imports',
    'SCA flags a vulnerable library; SAST finds code that imports/uses that library. Uses production-branch SAST findings.',
    'cross_tool',
    '{"match_on": "package_to_import", "categories": ["SCA", "SAST"], "same_application": true, "sast_branch": "production"}'::JSONB,
    'Medium',
    8
),
(
    'CR-4: DAST endpoint matched to SAST handler',
    'DAST finds vulnerability at a URL; SAST found weakness in the code handling that route. Uses production-branch SAST findings.',
    'cross_tool',
    '{"match_on": "url_to_handler", "categories": ["DAST", "SAST"], "same_application": true, "sast_branch": "production"}'::JSONB,
    'Medium',
    7
),
(
    'CR-5: Same rule_id across multiple files (SAST pattern)',
    'Systemic pattern: the same code weakness repeated across multiple files in one application. Operates within each branch independently.',
    'intra_tool',
    '{"match_on": "rule_id_multi_file", "categories": ["SAST"], "same_application": true, "same_branch": true}'::JSONB,
    'High',
    6
),
(
    'CR-6: Same CWE in same file (SAST cluster)',
    'Multiple weaknesses of the same class concentrated in one file. Operates within each branch independently.',
    'intra_tool',
    '{"match_on": "cwe_same_file", "categories": ["SAST"], "same_application": true, "same_branch": true}'::JSONB,
    'High',
    5
);

-- ============================================================
-- SEED: DEFAULT APP CODE PATTERNS
-- ============================================================

INSERT INTO app_code_patterns (source_tool, field_name, regex_pattern, priority, description) VALUES
('JFrog Xray', 'path', '^[^/]+/(?P<app_code>[^/]+)/', 10, 'Second segment of repo path'),
('JFrog Xray', 'impacted_artifact', 'gav://com\.\w+\.(?P<app_code>\w+):', 5, 'Third segment of GAV groupId'),
('Tenable WAS', 'DNS Name', '^[st](?P<app_code>[^.]+)\.', 10, 'Strip s/t env prefix from subdomain'),
('Tenable WAS', 'DNS Name', '^(?P<app_code>[^.]+)\.', 5, 'Full first subdomain (fallback, no strip)'),
('Tenable WAS', 'URL', 'https?://[st](?P<app_code>[^.]+)\.', 10, 'Strip s/t env prefix from URL subdomain'),
('Tenable WAS', 'URL', 'https?://(?P<app_code>[^.]+)\.', 5, 'Full subdomain from URL (fallback)');

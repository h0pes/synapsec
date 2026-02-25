//! Configurable regex-based app code extraction from scanner fields.
//!
//! Tries patterns in priority order (highest first). The first match
//! with a non-empty `app_code` named capture group wins.

use regex::Regex;

/// A single app code extraction pattern (loaded from DB or test fixture).
#[derive(Debug, Clone)]
pub struct PatternEntry {
    pub field_name: String,
    pub regex_pattern: String,
    pub priority: i32,
}

/// Resolve an app code from field name/value pairs using the given patterns.
///
/// Patterns are tried in descending priority order. Returns the first
/// non-empty `app_code` capture, or `None` if nothing matches.
pub fn resolve(patterns: &[PatternEntry], fields: &[(String, String)]) -> Option<String> {
    let mut sorted: Vec<&PatternEntry> = patterns.iter().collect();
    sorted.sort_by(|a, b| b.priority.cmp(&a.priority));

    for pattern in sorted {
        let re = match Regex::new(&pattern.regex_pattern) {
            Ok(r) => r,
            Err(_) => continue,
        };

        for (field_name, field_value) in fields {
            if field_name != &pattern.field_name {
                continue;
            }
            if let Some(caps) = re.captures(field_value) {
                if let Some(m) = caps.name("app_code") {
                    let code = m.as_str().to_string();
                    if !code.is_empty() {
                        return Some(code);
                    }
                }
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xray_resolves_from_path() {
        let patterns = vec![PatternEntry {
            field_name: "path".to_string(),
            regex_pattern: r"^[^/]+/(?P<app_code>[^/]+)/".to_string(),
            priority: 10,
        }];
        let fields = vec![(
            "path".to_string(),
            "prod-release-local/gpe30/gpe30-set/v1.2.0-rc1/set-ear.ear".to_string(),
        )];
        let result = resolve(&patterns, &fields);
        assert_eq!(result, Some("gpe30".to_string()));
    }

    #[test]
    fn xray_resolves_from_gav() {
        let patterns = vec![PatternEntry {
            field_name: "impacted_artifact".to_string(),
            regex_pattern: r"gav://com\.\w+\.(?P<app_code>\w+):".to_string(),
            priority: 5,
        }];
        let fields = vec![(
            "impacted_artifact".to_string(),
            "gav://com.ourcompany.gpe30:set-ear:0.0.1".to_string(),
        )];
        let result = resolve(&patterns, &fields);
        assert_eq!(result, Some("gpe30".to_string()));
    }

    #[test]
    fn tenable_strips_env_prefix() {
        let patterns = vec![
            PatternEntry {
                field_name: "DNS Name".to_string(),
                regex_pattern: r"^[st](?P<app_code>[^.]+)\.".to_string(),
                priority: 10,
            },
            PatternEntry {
                field_name: "DNS Name".to_string(),
                regex_pattern: r"^(?P<app_code>[^.]+)\.".to_string(),
                priority: 5,
            },
        ];
        let fields = vec![(
            "DNS Name".to_string(),
            "sacronym.environment.env.domain.com".to_string(),
        )];
        let result = resolve(&patterns, &fields);
        assert_eq!(result, Some("acronym".to_string()));
    }

    #[test]
    fn tenable_no_prefix_uses_full_subdomain() {
        let patterns = vec![
            PatternEntry {
                field_name: "DNS Name".to_string(),
                regex_pattern: r"^[st](?P<app_code>[^.]+)\.".to_string(),
                priority: 10,
            },
            PatternEntry {
                field_name: "DNS Name".to_string(),
                regex_pattern: r"^(?P<app_code>[^.]+)\.".to_string(),
                priority: 5,
            },
        ];
        let fields = vec![(
            "DNS Name".to_string(),
            "myapp.environment.env.domain.com".to_string(),
        )];
        let result = resolve(&patterns, &fields);
        // 'm' is not 's' or 't', so pattern #1 won't match. Falls through to pattern #2.
        assert_eq!(result, Some("myapp".to_string()));
    }

    #[test]
    fn returns_none_when_no_match() {
        let patterns = vec![PatternEntry {
            field_name: "missing_field".to_string(),
            regex_pattern: r"(?P<app_code>\w+)".to_string(),
            priority: 10,
        }];
        let fields = vec![("other_field".to_string(), "some value".to_string())];
        let result = resolve(&patterns, &fields);
        assert_eq!(result, None);
    }

    #[test]
    fn priority_ordering_tries_highest_first() {
        let patterns = vec![
            PatternEntry {
                field_name: "path".to_string(),
                regex_pattern: r"^(?P<app_code>low_priority)".to_string(),
                priority: 1,
            },
            PatternEntry {
                field_name: "path".to_string(),
                regex_pattern: r"^[^/]+/(?P<app_code>[^/]+)/".to_string(),
                priority: 10,
            },
        ];
        let fields = vec![("path".to_string(), "repo/appcode/rest".to_string())];
        let result = resolve(&patterns, &fields);
        assert_eq!(result, Some("appcode".to_string()));
    }
}

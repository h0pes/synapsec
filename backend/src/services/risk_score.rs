//! Composite risk score computation using a 5-factor weighted model.
//!
//! Factors and default weights (configurable via system_config):
//! - Normalized Severity: 30%
//! - Asset Criticality: 25%
//! - Exploitability: 20%
//! - Finding Age: 15% (dynamic — computed relative to SLA)
//! - Correlation Density: 10%

use serde::{Deserialize, Serialize};

use crate::models::application::AssetCriticality;
use crate::models::finding::SeverityLevel;
use crate::models::finding_sca::ExploitMaturity;

/// Factor weights for risk score computation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskWeights {
    pub normalized_severity: f32,
    pub asset_criticality: f32,
    pub exploitability: f32,
    pub finding_age: f32,
    pub correlation_density: f32,
}

impl Default for RiskWeights {
    fn default() -> Self {
        Self {
            normalized_severity: 0.30,
            asset_criticality: 0.25,
            exploitability: 0.20,
            finding_age: 0.15,
            correlation_density: 0.10,
        }
    }
}

/// Input factors for computing the risk score.
#[derive(Debug, Clone)]
pub struct RiskFactors {
    pub severity: SeverityLevel,
    pub asset_criticality: Option<AssetCriticality>,
    pub exploitability: ExploitabilityInput,
    pub finding_age: FindingAgeInput,
    pub correlation_density: CorrelationInput,
}

/// Exploitability input from various sources.
#[derive(Debug, Clone)]
pub enum ExploitabilityInput {
    /// SCA: exploit maturity from vulnerability database.
    ScaMaturity(ExploitMaturity),
    /// SCA: EPSS score (0.0-1.0 probability).
    EpssScore(f32),
    /// SCA: Known exploited (CISA KEV).
    KnownExploited,
    /// DAST: confirmed exploitable during scan.
    DastConfirmed,
    /// SAST: taint analysis confidence level.
    SastConfidence(SastTaintConfidence),
    /// No exploitability data available.
    Unknown,
}

/// SAST taint analysis confidence.
#[derive(Debug, Clone)]
pub enum SastTaintConfidence {
    High,
    Medium,
    Low,
}

/// Finding age relative to SLA.
#[derive(Debug, Clone)]
pub struct FindingAgeInput {
    /// Ratio of elapsed time to SLA duration. 0.0 = just created, 1.0 = at SLA, 2.0+ = breached.
    pub sla_ratio: Option<f32>,
}

/// Correlation density input.
#[derive(Debug, Clone)]
pub struct CorrelationInput {
    /// Number of distinct tools that found correlated issues.
    pub distinct_tool_count: u32,
    /// Total number of correlated findings.
    pub correlated_finding_count: u32,
}

/// Computed risk score result.
#[derive(Debug, Clone, Serialize)]
pub struct RiskScore {
    pub composite_score: f32,
    pub priority: PriorityLevel,
    pub factor_scores: FactorScores,
}

/// Individual factor scores (0-100 each).
#[derive(Debug, Clone, Serialize)]
pub struct FactorScores {
    pub severity: f32,
    pub asset_criticality: f32,
    pub exploitability: f32,
    pub finding_age: f32,
    pub correlation_density: f32,
}

/// Priority level derived from composite score.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PriorityLevel {
    P1,
    P2,
    P3,
    P4,
    P5,
}

impl std::fmt::Display for PriorityLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::P1 => write!(f, "P1 — Critical"),
            Self::P2 => write!(f, "P2 — High"),
            Self::P3 => write!(f, "P3 — Medium"),
            Self::P4 => write!(f, "P4 — Low"),
            Self::P5 => write!(f, "P5 — Info"),
        }
    }
}

/// Compute the composite risk score.
pub fn compute(factors: &RiskFactors, weights: &RiskWeights) -> RiskScore {
    let severity_score = severity_to_score(&factors.severity);
    let criticality_score = criticality_to_score(factors.asset_criticality.as_ref());
    let exploit_score = exploitability_to_score(&factors.exploitability);
    let age_score = finding_age_to_score(&factors.finding_age);
    let correlation_score = correlation_to_score(&factors.correlation_density);

    let composite = severity_score * weights.normalized_severity
        + criticality_score * weights.asset_criticality
        + exploit_score * weights.exploitability
        + age_score * weights.finding_age
        + correlation_score * weights.correlation_density;

    // Clamp to 0-100
    let composite = composite.clamp(0.0, 100.0);

    let priority = score_to_priority(composite);

    RiskScore {
        composite_score: (composite * 10.0).round() / 10.0, // Round to 1 decimal
        priority,
        factor_scores: FactorScores {
            severity: severity_score,
            asset_criticality: criticality_score,
            exploitability: exploit_score,
            finding_age: age_score,
            correlation_density: correlation_score,
        },
    }
}

/// Map normalized severity to 0-100 score.
fn severity_to_score(severity: &SeverityLevel) -> f32 {
    match severity {
        SeverityLevel::Critical => 100.0,
        SeverityLevel::High => 80.0,
        SeverityLevel::Medium => 50.0,
        SeverityLevel::Low => 25.0,
        SeverityLevel::Info => 5.0,
    }
}

/// Map asset criticality to 0-100 score.
///
/// Falls back to 55.0 (Medium) when no application context is available.
fn criticality_to_score(criticality: Option<&AssetCriticality>) -> f32 {
    match criticality {
        Some(AssetCriticality::VeryHigh) => 100.0,
        Some(AssetCriticality::High) => 85.0,
        Some(AssetCriticality::MediumHigh) => 70.0,
        Some(AssetCriticality::Medium) => 55.0,
        Some(AssetCriticality::MediumLow) => 35.0,
        Some(AssetCriticality::Low) => 15.0,
        None => 55.0, // Default: Medium when no app context
    }
}

/// Map exploitability input to 0-100 score.
fn exploitability_to_score(input: &ExploitabilityInput) -> f32 {
    match input {
        ExploitabilityInput::KnownExploited => 100.0,
        ExploitabilityInput::DastConfirmed => 100.0,
        ExploitabilityInput::ScaMaturity(maturity) => match maturity {
            ExploitMaturity::Weaponized => 100.0,
            ExploitMaturity::Functional => 80.0,
            ExploitMaturity::ProofOfConcept => 50.0,
            ExploitMaturity::Unknown => 20.0,
        },
        ExploitabilityInput::EpssScore(score) => {
            // Map EPSS probability (0.0-1.0) to 0-100 with emphasis on high scores
            (score * 100.0).clamp(0.0, 100.0)
        }
        ExploitabilityInput::SastConfidence(confidence) => match confidence {
            SastTaintConfidence::High => 80.0,
            SastTaintConfidence::Medium => 50.0,
            SastTaintConfidence::Low => 20.0,
        },
        ExploitabilityInput::Unknown => 20.0, // Theoretical
    }
}

/// Map finding age (SLA ratio) to 0-100 score.
///
/// The score increases as findings age relative to their SLA deadline,
/// creating organic escalation pressure.
fn finding_age_to_score(input: &FindingAgeInput) -> f32 {
    match input.sla_ratio {
        Some(ratio) if ratio >= 2.0 => 100.0, // >2x SLA
        Some(ratio) if ratio >= 1.0 => 80.0,  // >1x SLA (breached)
        Some(ratio) if ratio >= 0.75 => 60.0, // >75% SLA
        Some(ratio) if ratio >= 0.50 => 40.0, // >50% SLA
        Some(_) => 20.0,                      // <50% SLA
        None => 20.0,                         // No SLA data
    }
}

/// Map correlation density to 0-100 score.
fn correlation_to_score(input: &CorrelationInput) -> f32 {
    if input.distinct_tool_count >= 3 || input.correlated_finding_count >= 3 {
        100.0
    } else if input.distinct_tool_count >= 2 {
        70.0
    } else if input.correlated_finding_count >= 2 {
        40.0
    } else {
        10.0 // Standalone finding
    }
}

/// Map composite score to priority level.
fn score_to_priority(score: f32) -> PriorityLevel {
    if score >= 80.0 {
        PriorityLevel::P1
    } else if score >= 60.0 {
        PriorityLevel::P2
    } else if score >= 40.0 {
        PriorityLevel::P3
    } else if score >= 20.0 {
        PriorityLevel::P4
    } else {
        PriorityLevel::P5
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_factors() -> RiskFactors {
        RiskFactors {
            severity: SeverityLevel::High,
            asset_criticality: Some(AssetCriticality::High),
            exploitability: ExploitabilityInput::Unknown,
            finding_age: FindingAgeInput { sla_ratio: Some(0.3) },
            correlation_density: CorrelationInput {
                distinct_tool_count: 1,
                correlated_finding_count: 1,
            },
        }
    }

    #[test]
    fn prd_appendix_e_example() {
        // PRD example: High severity, Tier 1 asset, taint analysis confirmed (High), internet-facing
        // Using refined design: Severity=80, AssetCrit=100 (VeryHigh), Exploit=80 (SastHigh), Age=20, Correlation=10
        let factors = RiskFactors {
            severity: SeverityLevel::High,
            asset_criticality: Some(AssetCriticality::VeryHigh),
            exploitability: ExploitabilityInput::SastConfidence(SastTaintConfidence::High),
            finding_age: FindingAgeInput { sla_ratio: Some(0.3) },
            correlation_density: CorrelationInput {
                distinct_tool_count: 1,
                correlated_finding_count: 1,
            },
        };

        let result = compute(&factors, &RiskWeights::default());

        // 80*0.30 + 100*0.25 + 80*0.20 + 20*0.15 + 10*0.10
        // = 24.0 + 25.0 + 16.0 + 3.0 + 1.0 = 69.0
        assert_eq!(result.composite_score, 69.0);
        assert_eq!(result.priority, PriorityLevel::P2);
    }

    #[test]
    fn critical_known_exploited_is_p1() {
        let factors = RiskFactors {
            severity: SeverityLevel::Critical,
            asset_criticality: Some(AssetCriticality::VeryHigh),
            exploitability: ExploitabilityInput::KnownExploited,
            finding_age: FindingAgeInput { sla_ratio: Some(1.5) },
            correlation_density: CorrelationInput {
                distinct_tool_count: 3,
                correlated_finding_count: 5,
            },
        };

        let result = compute(&factors, &RiskWeights::default());

        // 100*0.30 + 100*0.25 + 100*0.20 + 80*0.15 + 100*0.10
        // = 30 + 25 + 20 + 12 + 10 = 97.0
        assert_eq!(result.composite_score, 97.0);
        assert_eq!(result.priority, PriorityLevel::P1);
    }

    #[test]
    fn info_severity_standalone_is_p5() {
        let factors = RiskFactors {
            severity: SeverityLevel::Info,
            asset_criticality: Some(AssetCriticality::Low),
            exploitability: ExploitabilityInput::Unknown,
            finding_age: FindingAgeInput { sla_ratio: None },
            correlation_density: CorrelationInput {
                distinct_tool_count: 1,
                correlated_finding_count: 1,
            },
        };

        let result = compute(&factors, &RiskWeights::default());

        // 5*0.30 + 15*0.25 + 20*0.20 + 20*0.15 + 10*0.10
        // = 1.5 + 3.75 + 4.0 + 3.0 + 1.0 = 13.25 → 13.3
        assert_eq!(result.composite_score, 13.3); // Rounded to 1 decimal
        assert_eq!(result.priority, PriorityLevel::P5);
    }

    #[test]
    fn no_application_context_uses_medium_default() {
        let factors = RiskFactors {
            severity: SeverityLevel::Medium,
            asset_criticality: None, // No app context
            exploitability: ExploitabilityInput::Unknown,
            finding_age: FindingAgeInput { sla_ratio: Some(0.3) },
            correlation_density: CorrelationInput {
                distinct_tool_count: 1,
                correlated_finding_count: 1,
            },
        };

        let result = compute(&factors, &RiskWeights::default());

        assert_eq!(result.factor_scores.asset_criticality, 55.0);
        // 50*0.30 + 55*0.25 + 20*0.20 + 20*0.15 + 10*0.10
        // = 15.0 + 13.75 + 4.0 + 3.0 + 1.0 = 36.75 → 36.8
        assert_eq!(result.composite_score, 36.8);
        assert_eq!(result.priority, PriorityLevel::P4);
    }

    #[test]
    fn finding_age_escalation() {
        let weights = RiskWeights::default();
        let base = default_factors();

        // At <50% SLA
        let mut f = base.clone();
        f.finding_age = FindingAgeInput { sla_ratio: Some(0.3) };
        let r1 = compute(&f, &weights);

        // At >75% SLA
        f.finding_age = FindingAgeInput { sla_ratio: Some(0.8) };
        let r2 = compute(&f, &weights);

        // At >1x SLA (breached)
        f.finding_age = FindingAgeInput { sla_ratio: Some(1.2) };
        let r3 = compute(&f, &weights);

        // Score increases with age
        assert!(r2.composite_score > r1.composite_score);
        assert!(r3.composite_score > r2.composite_score);
    }

    #[test]
    fn correlation_density_scoring() {
        assert_eq!(
            correlation_to_score(&CorrelationInput {
                distinct_tool_count: 1,
                correlated_finding_count: 1
            }),
            10.0
        );
        assert_eq!(
            correlation_to_score(&CorrelationInput {
                distinct_tool_count: 1,
                correlated_finding_count: 2
            }),
            40.0
        );
        assert_eq!(
            correlation_to_score(&CorrelationInput {
                distinct_tool_count: 2,
                correlated_finding_count: 2
            }),
            70.0
        );
        assert_eq!(
            correlation_to_score(&CorrelationInput {
                distinct_tool_count: 3,
                correlated_finding_count: 3
            }),
            100.0
        );
    }

    #[test]
    fn custom_weights() {
        let factors = RiskFactors {
            severity: SeverityLevel::Critical,
            asset_criticality: Some(AssetCriticality::VeryHigh),
            exploitability: ExploitabilityInput::KnownExploited,
            finding_age: FindingAgeInput { sla_ratio: Some(2.5) },
            correlation_density: CorrelationInput {
                distinct_tool_count: 3,
                correlated_finding_count: 5,
            },
        };

        // All factors at 100 → should get 100 regardless of weights
        let result = compute(&factors, &RiskWeights::default());
        assert_eq!(result.composite_score, 100.0);

        // Custom weights that sum to 1.0
        let custom_weights = RiskWeights {
            normalized_severity: 0.50,
            asset_criticality: 0.20,
            exploitability: 0.15,
            finding_age: 0.10,
            correlation_density: 0.05,
        };
        let result2 = compute(&factors, &custom_weights);
        assert_eq!(result2.composite_score, 100.0);
    }

    #[test]
    fn epss_score_mapping() {
        assert_eq!(
            exploitability_to_score(&ExploitabilityInput::EpssScore(0.97)),
            97.0
        );
        assert_eq!(
            exploitability_to_score(&ExploitabilityInput::EpssScore(0.05)),
            5.0
        );
        assert_eq!(
            exploitability_to_score(&ExploitabilityInput::EpssScore(0.0)),
            0.0
        );
    }

    #[test]
    fn priority_level_display() {
        assert_eq!(PriorityLevel::P1.to_string(), "P1 — Critical");
        assert_eq!(PriorityLevel::P5.to_string(), "P5 — Info");
    }

    #[test]
    fn score_boundaries() {
        assert_eq!(score_to_priority(100.0), PriorityLevel::P1);
        assert_eq!(score_to_priority(80.0), PriorityLevel::P1);
        assert_eq!(score_to_priority(79.9), PriorityLevel::P2);
        assert_eq!(score_to_priority(60.0), PriorityLevel::P2);
        assert_eq!(score_to_priority(59.9), PriorityLevel::P3);
        assert_eq!(score_to_priority(40.0), PriorityLevel::P3);
        assert_eq!(score_to_priority(39.9), PriorityLevel::P4);
        assert_eq!(score_to_priority(20.0), PriorityLevel::P4);
        assert_eq!(score_to_priority(19.9), PriorityLevel::P5);
        assert_eq!(score_to_priority(0.0), PriorityLevel::P5);
    }
}

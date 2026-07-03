//! ISO 27001:2022 Annex A Controls
//!
//! Controls from ISO/IEC 27001:2022 for information security management.
//! The 2022 version reorganized controls into 4 themes (was 14 domains in 2013).

use serde::{Deserialize, Serialize};

/// ISO 27001:2022 Annex A Controls
///
/// Controls from ISO/IEC 27001:2022 for information security management.
/// The 2022 version reorganized controls into 4 themes (was 14 domains in 2013).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum Iso27001Control {
    // === A.5 Organizational Controls ===
    /// A.5.1: Policies for information security
    #[serde(rename = "A5_1")]
    A5_1,

    /// A.5.2: Information security roles and responsibilities
    #[serde(rename = "A5_2")]
    A5_2,

    /// A.5.3: Segregation of duties
    #[serde(rename = "A5_3")]
    A5_3,

    /// A.5.7: Threat intelligence
    #[serde(rename = "A5_7")]
    A5_7,

    /// A.5.15: Access control
    #[serde(rename = "A5_15")]
    A5_15,

    /// A.5.16: Identity management
    #[serde(rename = "A5_16")]
    A5_16,

    /// A.5.17: Authentication information
    #[serde(rename = "A5_17")]
    A5_17,

    /// A.5.18: Access rights
    #[serde(rename = "A5_18")]
    A5_18,

    /// A.5.22: Monitoring, review and change management of supplier services
    #[serde(rename = "A5_22")]
    A5_22,

    /// A.5.24: Information security incident management planning and preparation
    #[serde(rename = "A5_24")]
    A5_24,

    /// A.5.25: Assessment and decision on information security events
    #[serde(rename = "A5_25")]
    A5_25,

    /// A.5.26: Response to information security incidents
    #[serde(rename = "A5_26")]
    A5_26,

    /// A.5.28: Collection of evidence
    #[serde(rename = "A5_28")]
    A5_28,

    /// A.5.33: Protection of records
    #[serde(rename = "A5_33")]
    A5_33,

    /// A.5.34: Privacy and protection of PII
    #[serde(rename = "A5_34")]
    A5_34,

    // === A.6 People Controls ===
    /// A.6.1: Screening
    #[serde(rename = "A6_1")]
    A6_1,

    /// A.6.3: Information security awareness, education and training
    #[serde(rename = "A6_3")]
    A6_3,

    // === A.7 Physical Controls ===
    /// A.7.4: Physical security monitoring
    #[serde(rename = "A7_4")]
    A7_4,

    // === A.8 Technological Controls ===
    /// A.8.2: Privileged access rights
    #[serde(rename = "A8_2")]
    A8_2,

    /// A.8.3: Information access restriction
    #[serde(rename = "A8_3")]
    A8_3,

    /// A.8.4: Access to source code
    #[serde(rename = "A8_4")]
    A8_4,

    /// A.8.5: Secure authentication
    #[serde(rename = "A8_5")]
    A8_5,

    /// A.8.7: Protection against malware
    #[serde(rename = "A8_7")]
    A8_7,

    /// A.8.8: Management of technical vulnerabilities
    #[serde(rename = "A8_8")]
    A8_8,

    /// A.8.9: Configuration management
    #[serde(rename = "A8_9")]
    A8_9,

    /// A.8.10: Information deletion
    #[serde(rename = "A8_10")]
    A8_10,

    /// A.8.11: Data masking
    #[serde(rename = "A8_11")]
    A8_11,

    /// A.8.12: Data leakage prevention
    #[serde(rename = "A8_12")]
    A8_12,

    /// A.8.15: Logging
    ///
    /// Evidence: All audit log events
    #[serde(rename = "A8_15")]
    A8_15,

    /// A.8.16: Monitoring activities
    #[serde(rename = "A8_16")]
    A8_16,

    /// A.8.17: Clock synchronization
    #[serde(rename = "A8_17")]
    A8_17,

    /// A.8.20: Networks security
    #[serde(rename = "A8_20")]
    A8_20,

    /// A.8.24: Use of cryptography
    #[serde(rename = "A8_24")]
    A8_24,

    /// A.8.25: Secure development life cycle
    #[serde(rename = "A8_25")]
    A8_25,

    /// A.8.26: Application security requirements
    #[serde(rename = "A8_26")]
    A8_26,

    /// A.8.28: Secure coding
    #[serde(rename = "A8_28")]
    A8_28,
}

impl Iso27001Control {
    /// Get the control identifier string
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::A5_1 => "A.5.1",
            Self::A5_2 => "A.5.2",
            Self::A5_3 => "A.5.3",
            Self::A5_7 => "A.5.7",
            Self::A5_15 => "A.5.15",
            Self::A5_16 => "A.5.16",
            Self::A5_17 => "A.5.17",
            Self::A5_18 => "A.5.18",
            Self::A5_22 => "A.5.22",
            Self::A5_24 => "A.5.24",
            Self::A5_25 => "A.5.25",
            Self::A5_26 => "A.5.26",
            Self::A5_28 => "A.5.28",
            Self::A5_33 => "A.5.33",
            Self::A5_34 => "A.5.34",
            Self::A6_1 => "A.6.1",
            Self::A6_3 => "A.6.3",
            Self::A7_4 => "A.7.4",
            Self::A8_2 => "A.8.2",
            Self::A8_3 => "A.8.3",
            Self::A8_4 => "A.8.4",
            Self::A8_5 => "A.8.5",
            Self::A8_7 => "A.8.7",
            Self::A8_8 => "A.8.8",
            Self::A8_9 => "A.8.9",
            Self::A8_10 => "A.8.10",
            Self::A8_11 => "A.8.11",
            Self::A8_12 => "A.8.12",
            Self::A8_15 => "A.8.15",
            Self::A8_16 => "A.8.16",
            Self::A8_17 => "A.8.17",
            Self::A8_20 => "A.8.20",
            Self::A8_24 => "A.8.24",
            Self::A8_25 => "A.8.25",
            Self::A8_26 => "A.8.26",
            Self::A8_28 => "A.8.28",
        }
    }

    /// Get a human-readable description
    pub fn description(&self) -> &'static str {
        match self {
            Self::A5_1 => "Policies for information security",
            Self::A5_2 => "Information security roles and responsibilities",
            Self::A5_3 => "Segregation of duties",
            Self::A5_7 => "Threat intelligence",
            Self::A5_15 => "Access control",
            Self::A5_16 => "Identity management",
            Self::A5_17 => "Authentication information",
            Self::A5_18 => "Access rights",
            Self::A5_22 => "Monitoring of supplier services",
            Self::A5_24 => "Incident management planning",
            Self::A5_25 => "Assessment of security events",
            Self::A5_26 => "Response to security incidents",
            Self::A5_28 => "Collection of evidence",
            Self::A5_33 => "Protection of records",
            Self::A5_34 => "Privacy and protection of PII",
            Self::A6_1 => "Screening",
            Self::A6_3 => "Security awareness and training",
            Self::A7_4 => "Physical security monitoring",
            Self::A8_2 => "Privileged access rights",
            Self::A8_3 => "Information access restriction",
            Self::A8_4 => "Access to source code",
            Self::A8_5 => "Secure authentication",
            Self::A8_7 => "Protection against malware",
            Self::A8_8 => "Management of technical vulnerabilities",
            Self::A8_9 => "Configuration management",
            Self::A8_10 => "Information deletion",
            Self::A8_11 => "Data masking",
            Self::A8_12 => "Data leakage prevention",
            Self::A8_15 => "Logging",
            Self::A8_16 => "Monitoring activities",
            Self::A8_17 => "Clock synchronization",
            Self::A8_20 => "Networks security",
            Self::A8_24 => "Use of cryptography",
            Self::A8_25 => "Secure development life cycle",
            Self::A8_26 => "Application security requirements",
            Self::A8_28 => "Secure coding",
        }
    }

    /// Get the control theme (2022 reorganization)
    pub fn theme(&self) -> &'static str {
        match self {
            Self::A5_1
            | Self::A5_2
            | Self::A5_3
            | Self::A5_7
            | Self::A5_15
            | Self::A5_16
            | Self::A5_17
            | Self::A5_18
            | Self::A5_22
            | Self::A5_24
            | Self::A5_25
            | Self::A5_26
            | Self::A5_28
            | Self::A5_33
            | Self::A5_34 => "Organizational",
            Self::A6_1 | Self::A6_3 => "People",
            Self::A7_4 => "Physical",
            Self::A8_2
            | Self::A8_3
            | Self::A8_4
            | Self::A8_5
            | Self::A8_7
            | Self::A8_8
            | Self::A8_9
            | Self::A8_10
            | Self::A8_11
            | Self::A8_12
            | Self::A8_15
            | Self::A8_16
            | Self::A8_17
            | Self::A8_20
            | Self::A8_24
            | Self::A8_25
            | Self::A8_26
            | Self::A8_28 => "Technological",
        }
    }
}

impl std::fmt::Display for Iso27001Control {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_iso27001_control_display() {
        assert_eq!(Iso27001Control::A5_1.to_string(), "A.5.1");
        assert_eq!(Iso27001Control::A8_5.as_str(), "A.8.5");
        assert_eq!(Iso27001Control::A8_15.theme(), "Technological");
    }

    #[test]
    fn test_iso27001_themes() {
        // Organizational controls
        assert_eq!(Iso27001Control::A5_1.theme(), "Organizational");
        assert_eq!(Iso27001Control::A5_28.theme(), "Organizational");
        // People controls
        assert_eq!(Iso27001Control::A6_1.theme(), "People");
        // Physical controls
        assert_eq!(Iso27001Control::A7_4.theme(), "Physical");
        // Technological controls
        assert_eq!(Iso27001Control::A8_5.theme(), "Technological");
        assert_eq!(Iso27001Control::A8_26.theme(), "Technological");
    }

    /// All Annex A controls represented in the enum. Used to drive exhaustive
    /// table checks. If a variant is added, this list must be extended too
    /// (the `theme()`/`as_str()` matches are already exhaustive at compile time).
    const ALL: &[Iso27001Control] = &[
        Iso27001Control::A5_1,
        Iso27001Control::A5_2,
        Iso27001Control::A5_3,
        Iso27001Control::A5_7,
        Iso27001Control::A5_15,
        Iso27001Control::A5_16,
        Iso27001Control::A5_17,
        Iso27001Control::A5_18,
        Iso27001Control::A5_22,
        Iso27001Control::A5_24,
        Iso27001Control::A5_25,
        Iso27001Control::A5_26,
        Iso27001Control::A5_28,
        Iso27001Control::A5_33,
        Iso27001Control::A5_34,
        Iso27001Control::A6_1,
        Iso27001Control::A6_3,
        Iso27001Control::A7_4,
        Iso27001Control::A8_2,
        Iso27001Control::A8_3,
        Iso27001Control::A8_4,
        Iso27001Control::A8_5,
        Iso27001Control::A8_7,
        Iso27001Control::A8_8,
        Iso27001Control::A8_9,
        Iso27001Control::A8_10,
        Iso27001Control::A8_11,
        Iso27001Control::A8_12,
        Iso27001Control::A8_15,
        Iso27001Control::A8_16,
        Iso27001Control::A8_17,
        Iso27001Control::A8_20,
        Iso27001Control::A8_24,
        Iso27001Control::A8_25,
        Iso27001Control::A8_28,
    ];

    #[test]
    fn test_as_str_matches_dotted_control_id() {
        // The ISO control identifier for `Ax_y` is the dotted form `A.x.y`.
        // Derive the expectation mechanically from the variant name via its
        // Debug representation rather than hand-copying every string.
        for ctrl in ALL {
            let debug = format!("{ctrl:?}"); // e.g. "A8_15"
            let (theme_num, sub) = debug
                .trim_start_matches('A')
                .split_once('_')
                .expect("variant name has form Ax_y");
            let expected = format!("A.{theme_num}.{sub}");
            assert_eq!(ctrl.as_str(), expected, "as_str for {debug}");
            // Display delegates to as_str.
            assert_eq!(ctrl.to_string(), expected);
        }
    }

    #[test]
    fn test_theme_matches_control_number_prefix() {
        // 2022 reorganization: A.5 => Organizational, A.6 => People,
        // A.7 => Physical, A.8 => Technological. Derive the family from the
        // variant name so every variant is checked against the spec rule.
        for ctrl in ALL {
            let debug = format!("{ctrl:?}");
            let family = debug
                .trim_start_matches('A')
                .split('_')
                .next()
                .expect("variant name has form Ax_y");
            let expected = match family {
                "5" => "Organizational",
                "6" => "People",
                "7" => "Physical",
                "8" => "Technological",
                other => panic!("unexpected control family A{other}"),
            };
            assert_eq!(ctrl.theme(), expected, "theme for {debug}");
        }
    }

    #[test]
    fn test_description_non_empty_and_unique() {
        use std::collections::HashSet;
        let mut seen = HashSet::new();
        for ctrl in ALL {
            let desc = ctrl.description();
            assert!(!desc.is_empty(), "empty description for {ctrl:?}");
            // Each control should have a distinct description.
            assert!(
                seen.insert(desc),
                "duplicate description {desc:?} for {ctrl:?}"
            );
        }
    }

    #[test]
    fn test_serde_roundtrip_and_rename() {
        // Serialized form uses the SCREAMING variant name (e.g. "A8_15"),
        // NOT the dotted display form, and round-trips losslessly.
        for ctrl in ALL {
            let json = serde_json::to_string(ctrl).expect("serialize");
            let debug = format!("{ctrl:?}");
            assert_eq!(json, format!("\"{debug}\""), "serialized form for {debug}");
            let back: Iso27001Control = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(&back, ctrl);
        }
    }
}

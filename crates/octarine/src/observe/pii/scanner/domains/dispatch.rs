//! Canonical domain dispatch table
//!
//! Both scanner entry points — the full scan and the fast present-check —
//! iterate the single [`DOMAINS`] table below. Before issue #411 each
//! hand-rolled its own nine-domain `if config.scan_x { ... }` chain, so adding
//! a domain meant editing two places and missing one was a silent detection
//! gap. Adding a domain is now one new module plus one row here.

use super::super::super::config::PiiScannerConfig;
use super::super::super::types::PiiType;
use super::{
    biometric, financial, government, location, medical, network, organizational, personal, tokens,
};

/// One scannable PII domain: when it is enabled, how to scan it, and how to
/// cheaply test it for presence.
struct DomainEntry {
    /// Stable domain name, matching its module and its `scan_*` config flag.
    /// Used for diagnostics and to key the dispatch-parity test's samples.
    name: &'static str,
    /// Reads this domain's opt-in flag from the scanner config.
    enabled: fn(&PiiScannerConfig) -> bool,
    /// Full scan — appends every detected [`PiiType`] for this domain.
    scan: fn(&str, &mut Vec<PiiType>),
    /// Coarse pre-filter — cheaper than `scan` and deliberately not derived
    /// from it, so the present-check never has to collect matches.
    present: fn(&str) -> bool,
}

/// The canonical domain table. Order matches the historical dispatch order,
/// which determines the order of [`PiiType`]s in a scan result.
const DOMAINS: &[DomainEntry] = &[
    DomainEntry {
        name: "personal",
        enabled: |c| c.scan_personal,
        scan: personal::scan_personal,
        present: personal::is_personal_present,
    },
    DomainEntry {
        name: "financial",
        enabled: |c| c.scan_financial,
        scan: financial::scan_financial,
        present: financial::is_financial_present,
    },
    DomainEntry {
        name: "government",
        enabled: |c| c.scan_government,
        scan: government::scan_government,
        present: government::is_government_present,
    },
    DomainEntry {
        name: "medical",
        enabled: |c| c.scan_medical,
        scan: medical::scan_medical,
        present: medical::is_medical_present,
    },
    DomainEntry {
        name: "biometric",
        enabled: |c| c.scan_biometric,
        scan: biometric::scan_biometric,
        present: biometric::is_biometric_present,
    },
    DomainEntry {
        name: "location",
        enabled: |c| c.scan_location,
        scan: location::scan_location,
        present: location::is_location_present,
    },
    DomainEntry {
        name: "organizational",
        enabled: |c| c.scan_organizational,
        scan: organizational::scan_organizational,
        present: organizational::is_organizational_present,
    },
    DomainEntry {
        name: "network",
        enabled: |c| c.scan_network,
        scan: network::scan_network,
        present: network::is_network_present,
    },
    DomainEntry {
        name: "tokens",
        enabled: |c| c.scan_tokens,
        scan: tokens::scan_tokens,
        present: tokens::is_token_present,
    },
];

/// Internal scan function with config (for direct use and cache population)
pub(in super::super) fn scan_for_pii_uncached_with_config(
    text: &str,
    config: &PiiScannerConfig,
) -> Vec<PiiType> {
    let mut pii_types = Vec::new();

    for domain in DOMAINS.iter().filter(|d| (d.enabled)(config)) {
        (domain.scan)(text, &mut pii_types);
    }

    pii_types
}

/// Fast check if text contains any PII using a custom configuration
///
/// Short-circuits on the first enabled domain that reports a match — it never
/// collects the full [`PiiType`] list.
pub(in super::super) fn is_pii_present_with_config_impl(
    text: &str,
    config: &PiiScannerConfig,
) -> bool {
    DOMAINS
        .iter()
        .filter(|d| (d.enabled)(config))
        .any(|d| (d.present)(text))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    /// A positive sample per domain: text that domain must detect and no
    /// other domain is required to.
    ///
    /// Keyed by [`DomainEntry::name`] so a new table row with no sample fails
    /// `test_every_domain_has_a_sample` rather than silently going untested.
    const SAMPLES: &[(&str, &str)] = &[
        ("personal", "Contact Jane Doe at jane.doe@example.com"),
        ("financial", "Card 4111111111111111 on file"),
        ("government", "SSN: 517-29-8346"),
        ("medical", "Patient MRN: 1234567"),
        ("biometric", "fingerprint: a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"),
        ("location", "Coordinates 37.774929, -122.419416"),
        ("organizational", "Badge: BADGE# 98765"),
        ("network", "Server at 192.168.1.100"),
        ("tokens", "password=hunter2correcthorse"),
    ];

    fn sample_for(name: &str) -> &'static str {
        SAMPLES
            .iter()
            .find(|(domain, _)| *domain == name)
            .map(|(_, text)| *text)
            .unwrap_or_else(|| panic!("no test sample for domain `{name}` — add one to SAMPLES"))
    }

    /// Enable exactly one domain.
    fn only(name: &str) -> PiiScannerConfig {
        let mut config = PiiScannerConfig::none();
        match name {
            "personal" => config.scan_personal = true,
            "financial" => config.scan_financial = true,
            "government" => config.scan_government = true,
            "medical" => config.scan_medical = true,
            "biometric" => config.scan_biometric = true,
            "location" => config.scan_location = true,
            "organizational" => config.scan_organizational = true,
            "network" => config.scan_network = true,
            "tokens" => config.scan_tokens = true,
            other => panic!("no config flag wired for domain `{other}`"),
        }
        config
    }

    /// The parity guarantee this table exists to provide: for every domain,
    /// the full-scan path and the present-check path agree.
    ///
    /// Before issue #411 the two paths were hand-rolled separately, so a
    /// domain could be added to one and missed by the other. If a future row
    /// is wired into `scan` but its `present` is stale (or vice versa), the
    /// two assertions below disagree and this fails.
    #[test]
    fn test_scan_and_present_agree_for_every_domain() {
        for domain in DOMAINS {
            let config = only(domain.name);
            let text = sample_for(domain.name);

            let scanned = scan_for_pii_uncached_with_config(text, &config);
            assert!(
                !scanned.is_empty(),
                "domain `{}` scan path found nothing in its own sample: {text:?}",
                domain.name
            );

            assert!(
                is_pii_present_with_config_impl(text, &config),
                "domain `{}` present path disagrees with its scan path on {text:?} \
                 (scan found {scanned:?}) — the two dispatch paths have diverged",
                domain.name
            );
        }
    }

    /// Every table row must have a sample, so a newly added domain cannot
    /// slip past the parity test above by simply not being exercised.
    #[test]
    fn test_every_domain_has_a_sample() {
        for domain in DOMAINS {
            let _ = sample_for(domain.name);
        }
    }

    /// The table must cover every domain the config can enable. Fails if a
    /// `scan_*` flag is added to `PiiScannerConfig` without a `DOMAINS` row.
    #[test]
    fn test_table_covers_every_config_flag() {
        assert_eq!(
            DOMAINS.len(),
            PiiScannerConfig::all().enabled_count(),
            "DOMAINS table and PiiScannerConfig disagree on the domain count — \
             a scan_* flag was added without a table row (or vice versa)"
        );
    }

    /// A disabled domain must not be scanned by either path.
    #[test]
    fn test_disabled_domains_are_skipped() {
        let config = PiiScannerConfig::none();
        for domain in DOMAINS {
            let text = sample_for(domain.name);
            assert!(
                scan_for_pii_uncached_with_config(text, &config).is_empty(),
                "domain `{}` scanned despite every flag being disabled",
                domain.name
            );
            assert!(
                !is_pii_present_with_config_impl(text, &config),
                "domain `{}` reported present despite every flag being disabled",
                domain.name
            );
        }
    }
}

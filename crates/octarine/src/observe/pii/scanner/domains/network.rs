//! Network identifier scanning (IP, MAC, UUID, URL, domain, hostname, port)
//!
//! Part of the PII scanner domain split (issue #411).

use super::super::super::types::PiiType;
use crate::primitives::identifiers::NetworkIdentifierBuilder;

/// Scan for network identifiers (IP, MAC, UUID, URL, domain, hostname, port)
pub(super) fn scan_network(text: &str, pii_types: &mut Vec<PiiType>) {
    let network = NetworkIdentifierBuilder::new();

    if network.is_network_present(text) {
        if !network.find_ip_addresses_in_text(text).is_empty() {
            pii_types.push(PiiType::IpAddress);
        }
        if !network.find_mac_addresses_in_text(text).is_empty() {
            pii_types.push(PiiType::MacAddress);
        }
        if !network.find_uuids_in_text(text).is_empty() {
            pii_types.push(PiiType::Uuid);
        }
        if !network.find_urls_in_text(text).is_empty() {
            pii_types.push(PiiType::Url);
        }
        if !network.find_domains_in_text(text).is_empty() {
            pii_types.push(PiiType::Domain);
        }
    }

    // Hostname and Port are checked unconditionally: their regex patterns are
    // not part of `is_network_present`'s aggregate, so the guard above would
    // skip text containing only a hostname or port.
    if !network.find_hostnames_in_text(text).is_empty() {
        pii_types.push(PiiType::Hostname);
    }
    if !network.find_ports_in_text(text).is_empty() {
        pii_types.push(PiiType::Port);
    }
}

/// Coarse pre-filter for the network domain.
pub(super) fn is_network_present(text: &str) -> bool {
    let network = NetworkIdentifierBuilder::new();
    network.is_network_present(text)
        || !network.find_hostnames_in_text(text).is_empty()
        || !network.find_ports_in_text(text).is_empty()
}

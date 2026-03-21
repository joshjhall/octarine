//! Network identifier conversion and normalization (primitives layer)
//!
//! Pure conversion functions for network identifiers with NO logging.
//!
//! # Architecture
//!
//! This is part of **Layer 1 (primitives)** - pure functions with:
//! - No observe:: dependencies
//! - No logging or side effects
//! - Returns data only
//!
//! # Conversion Types
//!
//! - **URL Normalization**: Lowercase domains, remove trailing slashes, standardize protocols
//! - **IP Format Conversion**: IPv6 compression/expansion, IPv4-mapped IPv6
//! - **MAC Format Conversion**: Between colon, hyphen, and dot formats
//! - **Phone Formatting**: E.164, national, RFC 3966 formats

use crate::primitives::Problem;

// ============================================================================
// URL Normalization
// ============================================================================

/// Normalize a URL to canonical form
///
/// Normalizations applied:
/// - Lowercase scheme and domain (case-insensitive per RFC 3986)
/// - Remove default ports (:80 for http, :443 for https)
/// - Remove trailing slash from path (unless it's the root path)
/// - Remove fragment identifier (#anchor)
/// - Sort query parameters alphabetically
///
/// # Example
/// ```ignore
/// assert_eq!(
///     normalize_url("HTTPS://Example.COM:443/Path/?z=2&a=1#anchor"),
///     Ok("https://example.com/Path?a=1&z=2".to_string())
/// );
/// ```
pub fn normalize_url(url: &str) -> Result<String, Problem> {
    if url.is_empty() {
        return Err(Problem::Validation("URL cannot be empty".into()));
    }

    // Find protocol separator
    let protocol_end = url
        .find("://")
        .ok_or_else(|| Problem::Validation("URL must contain protocol (://)".into()))?;

    let protocol = url
        .get(..protocol_end)
        .ok_or_else(|| Problem::Validation("Invalid URL structure".into()))?;

    let protocol_remainder_start = protocol_end.saturating_add(3);
    let remainder = url
        .get(protocol_remainder_start..)
        .ok_or_else(|| Problem::Validation("Invalid URL structure".into()))?;

    // Lowercase protocol
    let protocol_lower = protocol.to_lowercase();

    // Find domain end (first slash, question mark, or hash)
    let domain_end = remainder.find(['/', '?', '#']).unwrap_or(remainder.len());
    let mut domain = remainder[..domain_end].to_string();

    // Extract path, query, fragment
    let rest = if domain_end < remainder.len() {
        &remainder[domain_end..]
    } else {
        ""
    };

    // Remove default ports
    if protocol_lower == "http" && domain.ends_with(":80") {
        let new_len = domain.len().saturating_sub(3);
        domain = domain.get(..new_len).unwrap_or(&domain).to_string();
    } else if protocol_lower == "https" && domain.ends_with(":443") {
        let new_len = domain.len().saturating_sub(4);
        domain = domain.get(..new_len).unwrap_or(&domain).to_string();
    }

    // Lowercase domain
    domain = domain.to_lowercase();

    // Split path, query, and fragment
    let (path, query_and_fragment) = if let Some(query_start) = rest.find('?') {
        let path_part = rest.get(..query_start).unwrap_or(rest);
        let query_start_plus_1 = query_start.saturating_add(1);
        let query_part = rest.get(query_start_plus_1..).unwrap_or("");
        (path_part, query_part)
    } else {
        (rest, "")
    };

    // Remove fragment
    let query = if let Some(fragment_start) = query_and_fragment.find('#') {
        query_and_fragment
            .get(..fragment_start)
            .unwrap_or(query_and_fragment)
    } else {
        query_and_fragment
    };

    // Sort query parameters
    let sorted_query = if !query.is_empty() {
        let mut params: Vec<&str> = query.split('&').collect();
        params.sort_unstable();
        format!("?{}", params.join("&"))
    } else {
        String::new()
    };

    // Remove trailing slash (unless root path)
    let normalized_path = if path.ends_with('/') && path.len() > 1 {
        let new_len = path.len().saturating_sub(1);
        path.get(..new_len).unwrap_or(path)
    } else if path.is_empty() {
        "/"
    } else {
        path
    };

    Ok(format!(
        "{}://{}{}{}",
        protocol_lower, domain, normalized_path, sorted_query
    ))
}

/// Canonicalize a domain name (lowercase, remove trailing dot)
///
/// # Example
/// ```ignore
/// assert_eq!(canonicalize_domain("Example.COM."), "example.com");
/// ```
#[must_use]
pub fn canonicalize_domain(domain: &str) -> String {
    let mut canonical = domain.to_lowercase();
    if canonical.ends_with('.') {
        canonical.pop();
    }
    canonical
}

// ============================================================================
// IP Address Format Conversion
// ============================================================================

/// Compress an IPv6 address (remove leading zeros, use :: for longest zero sequence)
///
/// # Example
/// ```ignore
/// assert_eq!(
///     compress_ipv6("2001:0db8:0000:0000:0000:0000:0000:0001"),
///     "2001:db8::1"
/// );
/// ```
#[must_use]
pub fn compress_ipv6(ip: &str) -> String {
    // Handle already compressed or short forms
    if ip.contains("::") || ip.len() < 15 {
        return ip.to_string();
    }

    let segments: Vec<&str> = ip.split(':').collect();
    if segments.len() != 8 {
        return ip.to_string(); // Invalid format, return as-is
    }

    // Remove leading zeros from each segment
    let trimmed: Vec<String> = segments
        .iter()
        .map(|s| {
            let trimmed = s.trim_start_matches('0');
            if trimmed.is_empty() {
                "0".to_string()
            } else {
                trimmed.to_string()
            }
        })
        .collect();

    // Find longest sequence of zeros
    let mut max_zero_start: usize = 0;
    let mut max_zero_len: usize = 0;
    let mut current_zero_start: usize = 0;
    let mut current_zero_len: usize = 0;

    for (i, segment) in trimmed.iter().enumerate() {
        if segment == "0" {
            if current_zero_len == 0 {
                current_zero_start = i;
            }
            current_zero_len = current_zero_len.saturating_add(1);
        } else {
            if current_zero_len > max_zero_len {
                max_zero_start = current_zero_start;
                max_zero_len = current_zero_len;
            }
            current_zero_len = 0;
        }
    }

    // Check final sequence
    if current_zero_len > max_zero_len {
        max_zero_start = current_zero_start;
        max_zero_len = current_zero_len;
    }

    // Only use :: if there are at least 2 consecutive zeros
    if max_zero_len < 2 {
        return trimmed.join(":");
    }

    // Build compressed form
    let before: Vec<String> = trimmed
        .get(..max_zero_start)
        .map(|s| s.to_vec())
        .unwrap_or_default();

    let after_start = max_zero_start.saturating_add(max_zero_len);
    let after: Vec<String> = trimmed
        .get(after_start..)
        .map(|s| s.to_vec())
        .unwrap_or_default();

    if before.is_empty() && after.is_empty() {
        // All zeros: ::
        "::".to_string()
    } else if before.is_empty() {
        // Leading zeros: ::after
        format!("::{}", after.join(":"))
    } else if after.is_empty() {
        // Trailing zeros: before::
        format!("{}::", before.join(":"))
    } else {
        // Middle zeros: before::after
        format!("{}::{}", before.join(":"), after.join(":"))
    }
}

/// Expand an IPv6 address to full canonical form (all 8 segments, 4 hex digits each)
///
/// # Example
/// ```ignore
/// assert_eq!(
///     expand_ipv6("2001:db8::1"),
///     "2001:0db8:0000:0000:0000:0000:0000:0001"
/// );
/// ```
pub fn expand_ipv6(ip: &str) -> Result<String, Problem> {
    if ip == "::1" {
        return Ok("0000:0000:0000:0000:0000:0000:0000:0001".to_string());
    }

    if ip == "::" {
        return Ok("0000:0000:0000:0000:0000:0000:0000:0000".to_string());
    }

    let mut segments = Vec::new();

    if let Some(double_colon_pos) = ip.find("::") {
        // Split at ::
        let before = ip.get(..double_colon_pos).unwrap_or("");
        let after_start = double_colon_pos.saturating_add(2);
        let after = ip.get(after_start..).unwrap_or("");

        // Parse before
        if !before.is_empty() {
            segments.extend(before.split(':'));
        }

        // Calculate missing zeros
        let after_segments: Vec<&str> = if after.is_empty() {
            vec![]
        } else {
            after.split(':').collect()
        };

        let total_existing = segments.len().saturating_add(after_segments.len());
        let missing = 8_usize.saturating_sub(total_existing);

        // Add missing zeros
        segments.reserve(missing);
        #[allow(clippy::same_item_push)] // Intentionally pushing "0" to fill IPv6 segments
        for _ in 0..missing {
            segments.push("0");
        }

        // Add after segments
        segments.extend(after_segments);
    } else {
        segments.extend(ip.split(':'));
    }

    if segments.len() != 8 {
        return Err(Problem::Validation("Invalid IPv6 format".into()));
    }

    // Pad each segment to 4 hex digits
    let expanded: Vec<String> = segments.iter().map(|s| format!("{:0>4}", s)).collect();

    Ok(expanded.join(":"))
}

/// Convert IPv4 address to IPv4-mapped IPv6 format (::ffff:a.b.c.d)
///
/// # Example
/// ```ignore
/// assert_eq!(ipv4_to_ipv6_mapped("192.168.1.1"), Ok("::ffff:192.168.1.1".to_string()));
/// ```
pub fn ipv4_to_ipv6_mapped(ipv4: &str) -> Result<String, Problem> {
    // Validate IPv4 format
    let octets: Vec<&str> = ipv4.split('.').collect();
    if octets.len() != 4 {
        return Err(Problem::Validation("Invalid IPv4 format".into()));
    }

    // Validate each octet is a valid u8 (0-255)
    for octet in &octets {
        let _val: u8 = octet
            .parse()
            .map_err(|_| Problem::Validation("Invalid IPv4 octet".into()))?;
        // No need to check > 255 since u8 max is 255
    }

    Ok(format!("::ffff:{}", ipv4))
}

// ============================================================================
// MAC Address Format Conversion
// ============================================================================

/// Convert MAC address to colon format (AA:BB:CC:DD:EE:FF)
///
/// # Example
/// ```ignore
/// assert_eq!(mac_to_colon("AA-BB-CC-DD-EE-FF"), Ok("AA:BB:CC:DD:EE:FF".to_string()));
/// assert_eq!(mac_to_colon("AABB.CCDD.EEFF"), Ok("AA:BB:CC:DD:EE:FF".to_string()));
/// ```
pub fn mac_to_colon(mac: &str) -> Result<String, Problem> {
    let normalized = mac.replace([':', '-', '.'], "").to_uppercase();

    if normalized.len() != 12 {
        return Err(Problem::Validation(
            "MAC address must be 12 hex characters".into(),
        ));
    }

    // Validate all hex
    if !normalized.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(Problem::Validation(
            "MAC address contains invalid characters".into(),
        ));
    }

    // Format as AA:BB:CC:DD:EE:FF
    Ok(format!(
        "{}:{}:{}:{}:{}:{}",
        &normalized[0..2],
        &normalized[2..4],
        &normalized[4..6],
        &normalized[6..8],
        &normalized[8..10],
        &normalized[10..12]
    ))
}

/// Convert MAC address to hyphen format (AA-BB-CC-DD-EE-FF)
///
/// # Example
/// ```ignore
/// assert_eq!(mac_to_hyphen("AA:BB:CC:DD:EE:FF"), Ok("AA-BB-CC-DD-EE-FF".to_string()));
/// ```
pub fn mac_to_hyphen(mac: &str) -> Result<String, Problem> {
    let colon_format = mac_to_colon(mac)?;
    Ok(colon_format.replace(':', "-"))
}

/// Convert MAC address to Cisco dot format (AABB.CCDD.EEFF)
///
/// # Example
/// ```ignore
/// assert_eq!(mac_to_cisco_dot("AA:BB:CC:DD:EE:FF"), Ok("AABB.CCDD.EEFF".to_string()));
/// ```
pub fn mac_to_cisco_dot(mac: &str) -> Result<String, Problem> {
    let normalized = mac.replace([':', '-', '.'], "").to_uppercase();

    if normalized.len() != 12 {
        return Err(Problem::Validation(
            "MAC address must be 12 hex characters".into(),
        ));
    }

    if !normalized.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(Problem::Validation(
            "MAC address contains invalid characters".into(),
        ));
    }

    // Format as AABB.CCDD.EEFF
    Ok(format!(
        "{}.{}.{}",
        &normalized[0..4],
        &normalized[4..8],
        &normalized[8..12]
    ))
}

/// Normalize MAC address to canonical format (uppercase, colon-separated)
///
/// # Example
/// ```ignore
/// assert_eq!(normalize_mac("aa-bb-cc-dd-ee-ff"), Ok("AA:BB:CC:DD:EE:FF".to_string()));
/// ```
pub fn normalize_mac(mac: &str) -> Result<String, Problem> {
    mac_to_colon(mac)
}

// ============================================================================
// Phone Number Formatting
// ============================================================================

/// Convert phone number to E.164 international format (+[country][number])
///
/// Removes all formatting and ensures + prefix
///
/// # Example
/// ```ignore
/// assert_eq!(to_phone_e164("1-555-123-4567"), "+15551234567");
/// assert_eq!(to_phone_e164("+44 20 7946 0958"), "+442079460958");
/// ```
#[must_use]
pub fn to_phone_e164(phone: &str) -> String {
    // Remove all non-digit characters except leading +
    let mut digits = String::new();

    for (i, ch) in phone.chars().enumerate() {
        if ch == '+' && i == 0 {
            // Skip the leading +, we'll add it back
            continue;
        } else if ch.is_ascii_digit() {
            digits.push(ch);
        }
    }

    // Always ensure + prefix
    format!("+{}", digits)
}

/// Convert phone number to RFC 3966 tel URI format
///
/// # Example
/// ```ignore
/// assert_eq!(to_phone_tel_uri("+1-555-123-4567"), "tel:+1-555-123-4567");
/// ```
#[must_use]
pub fn to_phone_tel_uri(phone: &str) -> String {
    let e164 = to_phone_e164(phone);
    format!("tel:{}", e164)
}

/// Convert phone number to national format (country-specific)
///
/// For US/Canada (+1): (555) 123-4567
/// For others: returns E.164 format
///
/// # Example
/// ```ignore
/// assert_eq!(to_phone_national("+15551234567"), "(555) 123-4567");
/// ```
#[must_use]
pub fn to_phone_national(phone: &str) -> String {
    let e164 = to_phone_e164(phone);

    // US/Canada format
    if e164.starts_with("+1") && e164.len() == 12 {
        let area = &e164[2..5];
        let exchange = &e164[5..8];
        let number = &e164[8..12];
        return format!("({}) {}-{}", area, exchange, number);
    }

    // Default to E.164
    e164
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::indexing_slicing)]
    use super::*;

    // ===== URL Normalization Tests =====

    #[test]
    fn test_normalize_url() {
        assert_eq!(
            normalize_url("HTTPS://Example.COM:443/Path/?z=2&a=1#anchor")
                .expect("Valid URL should normalize"),
            "https://example.com/Path?a=1&z=2"
        );
        assert_eq!(
            normalize_url("http://example.com:80/").expect("Valid URL should normalize"),
            "http://example.com/"
        );
        assert!(normalize_url("").is_err());
        assert!(normalize_url("not-a-url").is_err());
    }

    #[test]
    fn test_canonicalize_domain() {
        assert_eq!(canonicalize_domain("Example.COM."), "example.com");
        assert_eq!(canonicalize_domain("example.com"), "example.com");
    }

    // ===== IPv6 Conversion Tests =====

    #[test]
    fn test_compress_ipv6() {
        assert_eq!(
            compress_ipv6("2001:0db8:0000:0000:0000:0000:0000:0001"),
            "2001:db8::1"
        );
        assert_eq!(compress_ipv6("2001:db8::1"), "2001:db8::1"); // Already compressed
    }

    #[test]
    fn test_expand_ipv6() {
        assert_eq!(
            expand_ipv6("2001:db8::1").expect("Valid IPv6 should expand"),
            "2001:0db8:0000:0000:0000:0000:0000:0001"
        );
        assert_eq!(
            expand_ipv6("::1").expect("Valid IPv6 should expand"),
            "0000:0000:0000:0000:0000:0000:0000:0001"
        );
        assert_eq!(
            expand_ipv6("::").expect("Valid IPv6 should expand"),
            "0000:0000:0000:0000:0000:0000:0000:0000"
        );
    }

    #[test]
    fn test_ipv4_to_ipv6_mapped() {
        assert_eq!(
            ipv4_to_ipv6_mapped("192.168.1.1").expect("Valid IPv4 should map to IPv6"),
            "::ffff:192.168.1.1"
        );
        assert!(ipv4_to_ipv6_mapped("256.1.1.1").is_err());
        assert!(ipv4_to_ipv6_mapped("not-an-ip").is_err());
    }

    // ===== MAC Address Conversion Tests =====

    #[test]
    fn test_mac_to_colon() {
        assert_eq!(
            mac_to_colon("AA-BB-CC-DD-EE-FF").expect("Valid MAC should convert to colon format"),
            "AA:BB:CC:DD:EE:FF"
        );
        assert_eq!(
            mac_to_colon("AABB.CCDD.EEFF").expect("Valid MAC should convert to colon format"),
            "AA:BB:CC:DD:EE:FF"
        );
        assert_eq!(
            mac_to_colon("aabbccddeeff").expect("Valid MAC should convert to colon format"),
            "AA:BB:CC:DD:EE:FF"
        );
    }

    #[test]
    fn test_mac_to_hyphen() {
        assert_eq!(
            mac_to_hyphen("AA:BB:CC:DD:EE:FF").expect("Valid MAC should convert to hyphen format"),
            "AA-BB-CC-DD-EE-FF"
        );
    }

    #[test]
    fn test_mac_to_cisco_dot() {
        assert_eq!(
            mac_to_cisco_dot("AA:BB:CC:DD:EE:FF")
                .expect("Valid MAC should convert to Cisco dot format"),
            "AABB.CCDD.EEFF"
        );
    }

    #[test]
    fn test_normalize_mac() {
        assert_eq!(
            normalize_mac("aa-bb-cc-dd-ee-ff").expect("Valid MAC should normalize"),
            "AA:BB:CC:DD:EE:FF"
        );
        assert!(normalize_mac("invalid").is_err());
    }

    // ===== Phone Formatting Tests =====

    #[test]
    fn test_to_phone_e164() {
        assert_eq!(to_phone_e164("1-555-123-4567"), "+15551234567");
        assert_eq!(to_phone_e164("+44 20 7946 0958"), "+442079460958");
        assert_eq!(to_phone_e164("+1 (555) 123-4567"), "+15551234567");
    }

    #[test]
    fn test_to_phone_tel_uri() {
        assert_eq!(to_phone_tel_uri("+1-555-123-4567"), "tel:+15551234567");
    }

    #[test]
    fn test_to_phone_national() {
        assert_eq!(to_phone_national("+15551234567"), "(555) 123-4567");
        // Non-US number returns E.164
        assert_eq!(to_phone_national("+442079460958"), "+442079460958");
    }

    // ===== Edge Case Tests =====

    #[test]
    fn test_mac_invalid_length() {
        assert!(mac_to_colon("AA:BB:CC").is_err());
        assert!(mac_to_colon("AA:BB:CC:DD:EE:FF:GG").is_err());
    }

    #[test]
    fn test_mac_invalid_characters() {
        assert!(mac_to_colon("ZZ:YY:XX:WW:VV:UU").is_err());
    }

    #[test]
    fn test_ipv6_invalid() {
        assert!(expand_ipv6("not:valid:ipv6").is_err());
    }
}

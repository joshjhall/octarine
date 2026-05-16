//! UUID, MAC address, IP address, hostname, domain, port, JWT, generic phone,
//! and SSH key/fingerprint patterns
//!
//! These patterns identify "things on the network" rather than secrets — the
//! identifiers used to route, reach, or distinguish hosts and tokens.

#![allow(clippy::expect_used)]
// SAFETY: All regex patterns in this module are hardcoded and verified at compile time.

use once_cell::sync::Lazy;
use regex::Regex;

// UUID patterns
/// UUID v4 pattern (random UUIDs)
/// Example: "550e8400-e29b-41d4-a716-446655440000"
pub static UUID_V4: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b",
    )
    .expect("BUG: Invalid regex pattern")
});

/// UUID v5 pattern (namespace-based SHA-1 UUIDs)
/// Example: "550e8400-e29b-41d4-5716-446655440000"
pub static UUID_V5: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-5[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b",
    )
    .expect("BUG: Invalid regex pattern")
});

/// UUID any version pattern (versions 1-5)
/// Example: "550e8400-e29b-41d4-a716-446655440000"
pub static UUID_ANY: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b",
    )
    .expect("BUG: Invalid regex pattern")
});

// MAC address patterns
/// MAC address with colons
/// Example: "00:1B:44:11:3A:B7"
pub static MAC_COLON: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}").expect("BUG: Invalid regex pattern")
});

/// MAC address with hyphens
/// Example: "00-1B-44-11-3A-B7"
pub static MAC_HYPHEN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"([0-9A-Fa-f]{2}-){5}[0-9A-Fa-f]{2}").expect("BUG: Invalid regex pattern")
});

/// MAC address with dots (Cisco format)
/// Example: "001B.4411.3AB7"
pub static MAC_DOT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}")
        .expect("BUG: Invalid regex pattern")
});

// IP address patterns
/// IPv4 address
/// Example: "192.168.1.1"
pub static IPV4: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
    )
    .expect("BUG: Invalid regex pattern")
});

/// IPv6 address (simplified pattern)
/// Example: "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
pub static IPV6: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|::1|::)")
        .expect("BUG: Invalid regex pattern")
});

/// IPv4 with label
/// Example: "IP: 192.168.1.1"
pub static IPV4_LABELED: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i:ip[\s:-]*address?[\s:-]*)(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)")
        .expect("BUG: Invalid regex pattern")
});

// Domain and hostname patterns
/// Domain name (without protocol)
/// Example: "example.com", "sub.domain.co.uk"
/// Pattern: Must have at least one dot and valid TLD (2-63 chars)
pub static DOMAIN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}\b")
        .expect("BUG: Invalid regex pattern")
});

/// Hostname (with optional port)
/// Example: "server01", "db-primary:5432", "cache-node-3"
/// Pattern: Alphanumeric + hyphens, 1-63 chars, optional :port
pub static HOSTNAME: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?::\d{1,5})?\b")
        .expect("BUG: Invalid regex pattern")
});

/// Port number (standalone or with colon)
/// Example: ":8080", ":443", ":3000"
pub static PORT: Lazy<Regex> =
    Lazy::new(|| Regex::new(r":([1-9]\d{0,4})\b").expect("BUG: Invalid regex pattern"));

// Phone patterns
/// International phone with country code
/// Example: "+1-555-123-4567"
pub static PHONE_INTL: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\+[1-9]\d{0,3}[-.\s]?\(?\d{1,4}\)?[-.\s]?\d{1,4}[-.\s]?\d{1,9}")
        .expect("BUG: Invalid regex pattern")
});

// JWT pattern
/// JWT token (base64url.base64url.base64url)
/// Example: "eyJhbGc...iOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWI...iJ9.SflKxwR...J8WQ4"
pub static JWT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b[A-Za-z0-9-_]{20,}\.[A-Za-z0-9-_]{20,}\.[A-Za-z0-9-_]{20,}\b")
        .expect("BUG: Invalid regex pattern")
});

// SSH key patterns
/// SSH public key pattern
/// Formats: ssh-rsa, ssh-ed25519, ssh-ecdsa, ssh-dss
/// Example: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC... user@host"
pub static SSH_PUBLIC_KEY: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\bssh-(rsa|ed25519|ecdsa|dss)\s+[A-Za-z0-9+/]+=*(?:\s+\S+)?\b")
        .expect("BUG: Invalid regex pattern")
});

/// SSH fingerprint MD5 format
/// Example: "16:27:ac:a5:76:28:2d:36:63:1b:56:4d:eb:df:a6:48"
pub static SSH_FINGERPRINT_MD5: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(?:[0-9a-f]{2}:){15}[0-9a-f]{2}\b").expect("BUG: Invalid regex pattern")
});

/// SSH fingerprint SHA256 format
/// Example: "SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8"
pub static SSH_FINGERPRINT_SHA256: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\bSHA256:[A-Za-z0-9+/]{43}=?\b").expect("BUG: Invalid regex pattern")
});

/// SSH private key header pattern
/// Matches various private key formats: RSA, DSA, EC, OPENSSH
/// Example: "-----BEGIN RSA PRIVATE KEY-----"
pub static SSH_PRIVATE_KEY_HEADER: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"-----BEGIN\s+(?:RSA|DSA|EC|OPENSSH|ENCRYPTED)?\s*PRIVATE\s+KEY-----")
        .expect("BUG: Invalid regex pattern")
});

//! Streaming identifier scanner with ring buffer for large documents
//!
//! Provides memory-efficient scanning of large documents by buffering detection
//! results and processing them in batches rather than holding all matches in memory.
//!
//! # Architecture
//!
//! This is part of **Layer 1 (primitives)** - pure functions with NO logging.
//! Uses `RingBuffer` from `primitives/common` for bounded memory usage.
//! Uses builder pattern to access all identifier detection functions while respecting
//! cascading visibility (no direct access to internal detection modules).
//!
//! # Usage
//!
//! ```rust,ignore
//! use crate::primitives::identifiers::streaming::StreamingScanner;
//!
//! // Create scanner with 1000-match buffer
//! let scanner = StreamingScanner::new(1000);
//!
//! // Scan large document for all identifier types
//! let matches = scanner.scan_all_identifiers(large_document);
//!
//! // Check statistics
//! let stats = scanner.stats();
//! println!("Processed {} matches, dropped {}", stats.total_written, stats.total_dropped);
//! ```
//!
//! # Performance Characteristics
//!
//! - Memory bounded by buffer capacity (not document size)
//! - O(n) time where n is document length
//! - Suitable for documents >10MB

use super::correlation;
use super::types::{IdentifierMatch, IdentifierType};
use super::{CorrelationConfig, CorrelationMatch};
use super::{
    biometric::BiometricIdentifierBuilder, credentials::CredentialIdentifierBuilder,
    financial::FinancialIdentifierBuilder, government::GovernmentIdentifierBuilder,
    location::LocationIdentifierBuilder, medical::MedicalIdentifierBuilder,
    network::NetworkIdentifierBuilder, organizational::OrganizationalIdentifierBuilder,
    personal::PersonalIdentifierBuilder,
};
use crate::primitives::collections::{BufferError, BufferStats, RingBuffer};

// ============================================================================
// Streaming Scanner
// ============================================================================

/// Memory-efficient streaming scanner for identifier detection
///
/// Uses a ring buffer to limit memory usage when processing large documents.
/// Older matches are automatically dropped when the buffer is full.
///
/// Scans all 8 identifier types:
/// - Personal: Email, phone, name, birthdate, username
/// - Financial: Credit card, bank account, routing number, payment token
/// - Government: SSN, driver's license, passport, tax ID, VIN, national ID
/// - Medical: MRN, NPI, insurance, prescription, medical code
/// - Network: IP, URL, UUID, MAC, hostname, phone (international)
/// - Biometric: Fingerprint, facial, iris, voice, DNA, template
/// - Organizational: Employee ID, student ID, badge number
/// - Location: GPS coordinates, postal code, street address
#[derive(Clone)]
pub struct StreamingScanner {
    buffer: RingBuffer<IdentifierMatch>,
    capacity: usize,
}

impl StreamingScanner {
    /// Create a new streaming scanner with specified buffer capacity
    ///
    /// # Arguments
    ///
    /// * `capacity` - Maximum number of matches to buffer (older matches dropped when exceeded)
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use crate::primitives::identifiers::streaming::StreamingScanner;
    ///
    /// // Buffer up to 1000 matches
    /// let scanner = StreamingScanner::new(1000);
    /// ```
    pub fn new(capacity: usize) -> Self {
        Self {
            buffer: RingBuffer::new(capacity),
            capacity,
        }
    }

    /// Scan text for all identifier types (all 8 categories)
    ///
    /// Scans for all identifier types across all categories:
    /// - Personal: Email, phone, name, birthdate, username
    /// - Financial: Credit card, bank account, routing number, payment token
    /// - Government: SSN, driver's license, passport, tax ID, VIN, national ID
    /// - Medical: MRN, NPI, insurance, prescription, medical code
    /// - Network: IP, URL, UUID, MAC, hostname, phone (international)
    /// - Biometric: Fingerprint, facial, iris, voice, DNA, template
    /// - Organizational: Employee ID, student ID, badge number
    /// - Location: GPS coordinates, postal code, street address
    ///
    /// Results are buffered and can be retrieved via `drain()` or `snapshot()`.
    ///
    /// # Returns
    ///
    /// Number of matches found (may exceed buffer capacity if document is large)
    pub fn scan_all_identifiers(&self, text: &str) -> usize {
        let mut total: usize = 0;

        // Create builders for each identifier category
        let personal = PersonalIdentifierBuilder::new();
        let financial = FinancialIdentifierBuilder::new();
        let government = GovernmentIdentifierBuilder::new();
        let medical = MedicalIdentifierBuilder::new();
        let network = NetworkIdentifierBuilder::new();
        let biometric = BiometricIdentifierBuilder::new();
        let organizational = OrganizationalIdentifierBuilder::new();
        let location = LocationIdentifierBuilder::new();

        // Scan personal identifiers
        for m in personal.detect_emails_in_text(text) {
            let _ = self.buffer.push(m);
            total = total.saturating_add(1);
        }
        for m in personal.detect_phones_in_text(text) {
            let _ = self.buffer.push(m);
            total = total.saturating_add(1);
        }
        for m in personal.detect_names_in_text(text) {
            let _ = self.buffer.push(m);
            total = total.saturating_add(1);
        }
        for m in personal.detect_birthdates_in_text(text) {
            let _ = self.buffer.push(m);
            total = total.saturating_add(1);
        }

        // Scan financial identifiers
        for m in financial.detect_all_in_text(text) {
            let _ = self.buffer.push(m);
            total = total.saturating_add(1);
        }

        // Scan government identifiers
        for m in government.find_ssns_in_text(text) {
            let _ = self.buffer.push(m);
            total = total.saturating_add(1);
        }
        for m in government.find_driver_licenses_in_text(text) {
            let _ = self.buffer.push(m);
            total = total.saturating_add(1);
        }
        for m in government.find_passports_in_text(text) {
            let _ = self.buffer.push(m);
            total = total.saturating_add(1);
        }
        for m in government.find_tax_ids_in_text(text) {
            let _ = self.buffer.push(m);
            total = total.saturating_add(1);
        }
        for m in government.find_national_ids_in_text(text) {
            let _ = self.buffer.push(m);
            total = total.saturating_add(1);
        }
        for m in government.find_vehicle_ids_in_text(text) {
            let _ = self.buffer.push(m);
            total = total.saturating_add(1);
        }

        // Scan medical identifiers
        for m in medical.find_all_in_text(text) {
            let _ = self.buffer.push(m);
            total = total.saturating_add(1);
        }

        // Scan network identifiers
        for m in network.find_ip_addresses_in_text(text) {
            let _ = self.buffer.push(m);
            total = total.saturating_add(1);
        }
        for m in network.find_urls_in_text(text) {
            let _ = self.buffer.push(m);
            total = total.saturating_add(1);
        }
        for m in network.find_uuids_in_text(text) {
            let _ = self.buffer.push(m);
            total = total.saturating_add(1);
        }
        for m in network.find_mac_addresses_in_text(text) {
            let _ = self.buffer.push(m);
            total = total.saturating_add(1);
        }

        // Scan biometric identifiers
        for m in biometric.detect_all_in_text(text) {
            let _ = self.buffer.push(m);
            total = total.saturating_add(1);
        }

        // Scan organizational identifiers
        for m in organizational.find_all_in_text(text) {
            let _ = self.buffer.push(m);
            total = total.saturating_add(1);
        }

        // Scan location identifiers
        for m in location.find_all_in_text(text) {
            let _ = self.buffer.push(m);
            total = total.saturating_add(1);
        }

        total
    }

    /// Scan text for specific identifier types only
    ///
    /// More efficient than `scan_all_identifiers` when you only need certain types.
    ///
    /// # Arguments
    ///
    /// * `text` - The text to scan
    /// * `types` - Which identifier types to scan for
    ///
    /// # Returns
    ///
    /// Number of matches found
    pub fn scan_types(&self, text: &str, types: &[IdentifierType]) -> usize {
        let mut total: usize = 0;

        for id_type in types {
            match id_type {
                // Personal identifiers
                IdentifierType::Email => {
                    let personal = PersonalIdentifierBuilder::new();
                    for m in personal.detect_emails_in_text(text) {
                        let _ = self.buffer.push(m);
                        total = total.saturating_add(1);
                    }
                }
                IdentifierType::PhoneNumber => {
                    let personal = PersonalIdentifierBuilder::new();
                    for m in personal.detect_phones_in_text(text) {
                        let _ = self.buffer.push(m);
                        total = total.saturating_add(1);
                    }
                }
                IdentifierType::PersonalName => {
                    let personal = PersonalIdentifierBuilder::new();
                    for m in personal.detect_names_in_text(text) {
                        let _ = self.buffer.push(m);
                        total = total.saturating_add(1);
                    }
                }
                IdentifierType::Birthdate => {
                    let personal = PersonalIdentifierBuilder::new();
                    for m in personal.detect_birthdates_in_text(text) {
                        let _ = self.buffer.push(m);
                        total = total.saturating_add(1);
                    }
                }
                IdentifierType::Username => {
                    // Not yet implemented in personal module
                    continue;
                }

                // Network identifiers
                IdentifierType::IpAddress => {
                    let network = NetworkIdentifierBuilder::new();
                    for m in network.find_ip_addresses_in_text(text) {
                        let _ = self.buffer.push(m);
                        total = total.saturating_add(1);
                    }
                }
                IdentifierType::Url => {
                    let network = NetworkIdentifierBuilder::new();
                    for m in network.find_urls_in_text(text) {
                        let _ = self.buffer.push(m);
                        total = total.saturating_add(1);
                    }
                }
                IdentifierType::Uuid => {
                    let network = NetworkIdentifierBuilder::new();
                    for m in network.find_uuids_in_text(text) {
                        let _ = self.buffer.push(m);
                        total = total.saturating_add(1);
                    }
                }
                IdentifierType::MacAddress => {
                    let network = NetworkIdentifierBuilder::new();
                    for m in network.find_mac_addresses_in_text(text) {
                        let _ = self.buffer.push(m);
                        total = total.saturating_add(1);
                    }
                }
                IdentifierType::Domain
                | IdentifierType::Hostname
                | IdentifierType::Port
                | IdentifierType::Jwt
                | IdentifierType::ApiKey
                | IdentifierType::SessionId => {
                    // These are detected by network module's find_all_in_text
                    // but we don't have specific find_X_in_text methods for them
                    // Skip for now in selective scan
                    continue;
                }

                // Financial identifiers
                IdentifierType::CreditCard => {
                    let financial = FinancialIdentifierBuilder::new();
                    for m in financial.detect_credit_cards_in_text(text) {
                        let _ = self.buffer.push(m);
                        total = total.saturating_add(1);
                    }
                }
                IdentifierType::BankAccount
                | IdentifierType::RoutingNumber
                | IdentifierType::PaymentToken => {
                    // Financial module covers all via detect_all_in_text
                    let financial = FinancialIdentifierBuilder::new();
                    for m in financial.detect_all_in_text(text) {
                        // Only push if it matches the requested type
                        if m.identifier_type == *id_type {
                            let _ = self.buffer.push(m);
                            total = total.saturating_add(1);
                        }
                    }
                }

                // Token/Key identifiers (not yet implemented in modules)
                IdentifierType::GitHubToken
                | IdentifierType::GitLabToken
                | IdentifierType::AwsAccessKey
                | IdentifierType::AwsSessionToken => {
                    // Not yet implemented in primitives
                    continue;
                }

                // Connection string detection
                IdentifierType::ConnectionString => {
                    let creds = CredentialIdentifierBuilder::new();
                    if creds.is_connection_string_with_credentials(text) {
                        total = total.saturating_add(1);
                    }
                }

                // Government identifiers
                IdentifierType::Ssn => {
                    let government = GovernmentIdentifierBuilder::new();
                    for m in government.find_ssns_in_text(text) {
                        let _ = self.buffer.push(m);
                        total = total.saturating_add(1);
                    }
                }
                IdentifierType::DriverLicense => {
                    let government = GovernmentIdentifierBuilder::new();
                    for m in government.find_driver_licenses_in_text(text) {
                        let _ = self.buffer.push(m);
                        total = total.saturating_add(1);
                    }
                }
                IdentifierType::Passport => {
                    let government = GovernmentIdentifierBuilder::new();
                    for m in government.find_passports_in_text(text) {
                        let _ = self.buffer.push(m);
                        total = total.saturating_add(1);
                    }
                }
                IdentifierType::TaxId => {
                    let government = GovernmentIdentifierBuilder::new();
                    for m in government.find_tax_ids_in_text(text) {
                        let _ = self.buffer.push(m);
                        total = total.saturating_add(1);
                    }
                }
                IdentifierType::NationalId => {
                    let government = GovernmentIdentifierBuilder::new();
                    for m in government.find_national_ids_in_text(text) {
                        let _ = self.buffer.push(m);
                        total = total.saturating_add(1);
                    }
                }
                IdentifierType::VehicleId => {
                    let government = GovernmentIdentifierBuilder::new();
                    for m in government.find_vehicle_ids_in_text(text) {
                        let _ = self.buffer.push(m);
                        total = total.saturating_add(1);
                    }
                }

                // Organizational identifiers
                IdentifierType::EmployeeId
                | IdentifierType::StudentId
                | IdentifierType::BadgeNumber => {
                    // Organizational module covers all via find_all_in_text
                    let organizational = OrganizationalIdentifierBuilder::new();
                    for m in organizational.find_all_in_text(text) {
                        if m.identifier_type == *id_type {
                            let _ = self.buffer.push(m);
                            total = total.saturating_add(1);
                        }
                    }
                }

                // Location identifiers
                IdentifierType::GPSCoordinate
                | IdentifierType::StreetAddress
                | IdentifierType::PostalCode => {
                    // Location module covers all via find_all_in_text
                    let location = LocationIdentifierBuilder::new();
                    for m in location.find_all_in_text(text) {
                        if m.identifier_type == *id_type {
                            let _ = self.buffer.push(m);
                            total = total.saturating_add(1);
                        }
                    }
                }

                // Medical identifiers
                IdentifierType::MedicalRecordNumber
                | IdentifierType::HealthInsurance
                | IdentifierType::Prescription
                | IdentifierType::ProviderID
                | IdentifierType::MedicalCode => {
                    // Medical module covers all via find_all_in_text
                    let medical = MedicalIdentifierBuilder::new();
                    for m in medical.find_all_in_text(text) {
                        if m.identifier_type == *id_type {
                            let _ = self.buffer.push(m);
                            total = total.saturating_add(1);
                        }
                    }
                }

                // Biometric identifiers
                IdentifierType::Fingerprint
                | IdentifierType::FacialRecognition
                | IdentifierType::IrisScan
                | IdentifierType::VoicePrint
                | IdentifierType::DNASequence
                | IdentifierType::BiometricTemplate => {
                    // Biometric module covers all via detect_all_in_text
                    let biometric = BiometricIdentifierBuilder::new();
                    for m in biometric.detect_all_in_text(text) {
                        if m.identifier_type == *id_type {
                            let _ = self.buffer.push(m);
                            total = total.saturating_add(1);
                        }
                    }
                }

                // Credential identifiers (context-based detection)
                IdentifierType::Password
                | IdentifierType::Pin
                | IdentifierType::SecurityAnswer
                | IdentifierType::Passphrase => {
                    // Credentials require context-based detection which works differently
                    // from pattern-based detection. They are detected via labels like
                    // "password:", "pin=", etc. Use CredentialIdentifierBuilder directly.
                    continue;
                }

                IdentifierType::Unknown => {
                    // Don't scan for unknown types
                    continue;
                }
            }
        }

        total
    }

    /// Drain all matches from the buffer
    ///
    /// Removes and returns all buffered matches. Buffer will be empty after this call.
    ///
    /// # Returns
    ///
    /// Vector of all matches currently in the buffer
    pub fn drain(&self) -> Vec<IdentifierMatch> {
        // Get current buffer length and drain all items
        let len = self.buffer.len().unwrap_or(0);
        self.buffer.drain(len).unwrap_or_default()
    }

    /// Get a snapshot of current matches without removing them
    ///
    /// # Returns
    ///
    /// Vector of all matches currently in the buffer (buffer remains unchanged)
    pub fn snapshot(&self) -> Vec<IdentifierMatch> {
        self.buffer.snapshot().unwrap_or_default()
    }

    /// Get buffer statistics
    ///
    /// # Returns
    ///
    /// Statistics about buffer usage (total written, dropped, etc.)
    pub fn stats(&self) -> BufferStats {
        self.buffer.stats().unwrap_or(BufferStats {
            current_size: 0,
            capacity: self.capacity(),
            total_written: 0,
            total_dropped: 0,
        })
    }

    /// Clear all matches from the buffer
    pub fn clear(&self) {
        let _ = self.buffer.clear();
    }

    /// Get current number of matches in buffer
    pub fn len(&self) -> usize {
        self.buffer.len().unwrap_or(0)
    }

    /// Check if buffer is empty
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty().unwrap_or(true)
    }

    /// Get buffer capacity
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Detect credential pairs from buffered matches using default configuration.
    ///
    /// Runs proximity and pair recognition on the matches already in the ring buffer,
    /// avoiding re-scanning the text. The original text is needed for line-distance
    /// calculation.
    ///
    /// Uses default proximity window: 5 lines, 500 chars, all pair types enabled.
    ///
    /// # Arguments
    ///
    /// * `text` - The original text that was scanned (needed for proximity calculation)
    ///
    /// # Returns
    ///
    /// A vec of `CorrelationMatch` values with `High` confidence.
    /// Empty if fewer than 2 buffered matches or no pairs found.
    #[must_use]
    pub fn detect_credential_pairs(&self, text: &str) -> Vec<CorrelationMatch> {
        self.detect_credential_pairs_with_config(text, &CorrelationConfig::default())
    }

    /// Detect credential pairs from buffered matches with custom configuration.
    ///
    /// Runs proximity and pair recognition on the matches already in the ring buffer,
    /// avoiding re-scanning the text. The original text is needed for line-distance
    /// calculation.
    ///
    /// # Arguments
    ///
    /// * `text` - The original text that was scanned (needed for proximity calculation)
    /// * `config` - Custom proximity window and enabled pair types
    ///
    /// # Returns
    ///
    /// A vec of `CorrelationMatch` values with `High` confidence.
    /// Empty if fewer than 2 buffered matches or no pairs found.
    #[must_use]
    pub fn detect_credential_pairs_with_config(
        &self,
        text: &str,
        config: &CorrelationConfig,
    ) -> Vec<CorrelationMatch> {
        let matches = self.snapshot();
        correlation::detect_credential_pairs_from_matches(text, &matches, config)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;
    use crate::primitives::identifiers::CredentialPairType;

    #[test]
    fn test_scanner_creation() {
        let scanner = StreamingScanner::new(100);
        assert_eq!(scanner.capacity(), 100);
        assert_eq!(scanner.len(), 0);
        assert!(scanner.is_empty());
    }

    #[test]
    fn test_scan_personal_identifiers() {
        let scanner = StreamingScanner::new(1000);
        let text = "Contact user@example.com or call +1-555-123-4567";

        let count = scanner.scan_all_identifiers(text);
        assert!(count >= 2); // At least email and phone

        let matches = scanner.snapshot();
        assert!(!matches.is_empty());
    }

    #[test]
    fn test_scan_types_selective() {
        let scanner = StreamingScanner::new(1000);
        let text = "Email: user@example.com, SSN: 123-45-6789";

        // Only scan for emails
        let count = scanner.scan_types(text, &[IdentifierType::Email]);
        assert!(count >= 1);

        scanner.clear();

        // Only scan for SSN
        let count = scanner.scan_types(text, &[IdentifierType::Ssn]);
        assert!(count >= 1);
    }

    #[test]
    fn test_buffer_overflow() {
        let scanner = StreamingScanner::new(5); // Small buffer
        let text = "user1@example.com user2@example.com user3@example.com user4@example.com user5@example.com user6@example.com";

        let count = scanner.scan_all_identifiers(text);
        assert!(count >= 6);

        // Buffer should have at most 5 items (capacity)
        assert!(scanner.len() <= 5);

        let stats = scanner.stats();
        assert!(stats.total_dropped > 0); // Some should be dropped
    }

    #[test]
    fn test_detect_credential_pairs_from_buffer() {
        let scanner = StreamingScanner::new(1000);
        // Scanner detects emails and UUIDs; these don't form a known credential pair,
        // so we verify the mechanism runs correctly and returns empty
        let text = "user@example.com and 550e8400-e29b-41d4-a716-446655440000";

        let count = scanner.scan_all_identifiers(text);
        assert!(count >= 2, "Should detect email and UUID");

        let pairs = scanner.detect_credential_pairs(text);
        // Email + UUID isn't a known credential pair type
        assert!(
            pairs.is_empty(),
            "Email + UUID should not form a credential pair: {pairs:?}"
        );
    }

    #[test]
    fn test_detect_credential_pairs_with_custom_config() {
        let scanner = StreamingScanner::new(1000);
        let text = "user@example.com and 550e8400-e29b-41d4-a716-446655440000";

        scanner.scan_all_identifiers(text);

        let config = CorrelationConfig {
            max_proximity_lines: 1,
            max_proximity_chars: 500,
            ..CorrelationConfig::default()
        };
        let pairs = scanner.detect_credential_pairs_with_config(text, &config);
        // Custom config works without error
        assert!(pairs.is_empty());
    }

    #[test]
    fn test_detect_credential_pairs_empty_buffer() {
        let scanner = StreamingScanner::new(1000);
        // No scan performed — buffer is empty
        let pairs = scanner.detect_credential_pairs("some text");
        assert!(pairs.is_empty(), "Empty buffer should produce no pairs");
    }

    #[test]
    fn test_detect_credential_pairs_after_overflow() {
        // Use a very small buffer so earlier matches get dropped
        let scanner = StreamingScanner::new(3);
        // Many emails — only last 3 matches kept
        let text =
            "a@x.com b@x.com c@x.com d@x.com e@x.com and 550e8400-e29b-41d4-a716-446655440000";

        scanner.scan_all_identifiers(text);
        let stats = scanner.stats();
        assert!(stats.total_dropped > 0, "Some matches should be dropped");

        // Pair detection should work on retained matches only (no panic)
        let pairs = scanner.detect_credential_pairs(text);
        assert!(pairs.len() <= stats.current_size);
    }

    #[test]
    fn test_detect_credential_pairs_uses_snapshot() {
        let scanner = StreamingScanner::new(1000);
        let text = "user@example.com";

        scanner.scan_all_identifiers(text);
        let buffer_before = scanner.len();

        // detect_credential_pairs should use snapshot (non-destructive)
        let _ = scanner.detect_credential_pairs(text);

        assert_eq!(
            scanner.len(),
            buffer_before,
            "Pair detection should not drain the buffer"
        );
    }
}

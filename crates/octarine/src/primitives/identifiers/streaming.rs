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
use super::entropy;
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
        for m in government.find_eins_in_text(text) {
            let _ = self.buffer.push(m);
            total = total.saturating_add(1);
        }
        for m in government.find_itins_in_text(text) {
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

        // Scan for high-entropy strings (potential secrets)
        for m in entropy::detect_high_entropy_strings_in_text(text) {
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
            total = total.saturating_add(self.scan_one_type(text, id_type));
        }
        total
    }

    /// Dispatch a single requested identifier type to the matching per-domain
    /// scanner. Returns the number of matches pushed to the buffer.
    fn scan_one_type(&self, text: &str, id_type: &IdentifierType) -> usize {
        // Each helper returns Some(count) for variants it owns, None otherwise.
        // The fall-through covers variants that have no dedicated scanner
        // (Unknown, unimplemented Username, etc.) and is therefore a no-op.
        self.scan_personal_type(text, id_type)
            .or_else(|| self.scan_network_type(text, id_type))
            .or_else(|| self.scan_financial_type(text, id_type))
            .or_else(|| self.scan_government_type(text, id_type))
            .or_else(|| self.scan_grouped_type(text, id_type))
            .or_else(|| self.scan_special_type(text, id_type))
            .unwrap_or(0)
    }

    /// Push every match from `matches` into the buffer and return the count.
    fn push_all(&self, matches: Vec<IdentifierMatch>) -> usize {
        let mut count: usize = 0;
        for m in matches {
            let _ = self.buffer.push(m);
            count = count.saturating_add(1);
        }
        count
    }

    /// Push every match whose type equals `wanted` and return the count.
    fn push_matching(&self, matches: Vec<IdentifierMatch>, wanted: &IdentifierType) -> usize {
        let mut count: usize = 0;
        for m in matches {
            if m.identifier_type == *wanted {
                let _ = self.buffer.push(m);
                count = count.saturating_add(1);
            }
        }
        count
    }

    fn scan_personal_type(&self, text: &str, id_type: &IdentifierType) -> Option<usize> {
        let personal = PersonalIdentifierBuilder::new();
        let matches = match id_type {
            IdentifierType::Email => personal.detect_emails_in_text(text),
            IdentifierType::PhoneNumber => personal.detect_phones_in_text(text),
            IdentifierType::PersonalName => personal.detect_names_in_text(text),
            IdentifierType::Birthdate => personal.detect_birthdates_in_text(text),
            // Username is not yet implemented in the personal module.
            IdentifierType::Username => return Some(0),
            _ => return None,
        };
        Some(self.push_all(matches))
    }

    fn scan_network_type(&self, text: &str, id_type: &IdentifierType) -> Option<usize> {
        let network = NetworkIdentifierBuilder::new();
        let matches = match id_type {
            IdentifierType::IpAddress => network.find_ip_addresses_in_text(text),
            IdentifierType::Url => network.find_urls_in_text(text),
            IdentifierType::Uuid => network.find_uuids_in_text(text),
            IdentifierType::MacAddress => network.find_mac_addresses_in_text(text),
            // Detected by network/token modules via find_all_in_text /
            // is_X predicates, but the streaming scanner has no dedicated
            // find_X_in_text methods for them. Skip for now in selective scan.
            IdentifierType::Domain
            | IdentifierType::Hostname
            | IdentifierType::Port
            | IdentifierType::Jwt
            | IdentifierType::ApiKey
            | IdentifierType::SessionId
            | IdentifierType::OAuthToken
            | IdentifierType::SshKey
            | IdentifierType::OnePasswordToken
            | IdentifierType::OnePasswordVaultRef
            | IdentifierType::BearerToken
            | IdentifierType::UrlWithCredentials => return Some(0),
            _ => return None,
        };
        Some(self.push_all(matches))
    }

    fn scan_financial_type(&self, text: &str, id_type: &IdentifierType) -> Option<usize> {
        let financial = FinancialIdentifierBuilder::new();
        match id_type {
            IdentifierType::CreditCard => {
                Some(self.push_all(financial.detect_credit_cards_in_text(text)))
            }
            IdentifierType::BankAccount
            | IdentifierType::RoutingNumber
            | IdentifierType::PaymentToken
            | IdentifierType::CryptoAddress
            | IdentifierType::Iban => {
                // Financial module covers all via detect_all_in_text; filter to
                // the requested type only.
                Some(self.push_matching(financial.detect_all_in_text(text), id_type))
            }
            _ => None,
        }
    }

    fn scan_government_type(&self, text: &str, id_type: &IdentifierType) -> Option<usize> {
        type Finder = fn(&GovernmentIdentifierBuilder, &str) -> Vec<IdentifierMatch>;
        type MatchesVariant = fn(&IdentifierType) -> bool;
        // Lookup of IdentifierType variant -> per-variant finder method. Lets
        // the helper stay flat regardless of how many country IDs we add.
        const FINDERS: &[(MatchesVariant, Finder)] = &[
            (
                |t| matches!(t, IdentifierType::Ssn),
                GovernmentIdentifierBuilder::find_ssns_in_text,
            ),
            (
                |t| matches!(t, IdentifierType::DriverLicense),
                GovernmentIdentifierBuilder::find_driver_licenses_in_text,
            ),
            (
                |t| matches!(t, IdentifierType::Passport),
                GovernmentIdentifierBuilder::find_passports_in_text,
            ),
            (
                |t| matches!(t, IdentifierType::Ein),
                GovernmentIdentifierBuilder::find_eins_in_text,
            ),
            (
                |t| matches!(t, IdentifierType::Itin),
                GovernmentIdentifierBuilder::find_itins_in_text,
            ),
            (
                |t| matches!(t, IdentifierType::TaxId),
                GovernmentIdentifierBuilder::find_tax_ids_in_text,
            ),
            (
                |t| matches!(t, IdentifierType::NationalId),
                GovernmentIdentifierBuilder::find_national_ids_in_text,
            ),
            (
                |t| matches!(t, IdentifierType::KoreaRrn),
                GovernmentIdentifierBuilder::find_korea_rrns_in_text,
            ),
            (
                |t| matches!(t, IdentifierType::AustraliaTfn),
                GovernmentIdentifierBuilder::find_australia_tfns_in_text,
            ),
            (
                |t| matches!(t, IdentifierType::AustraliaAbn),
                GovernmentIdentifierBuilder::find_australia_abns_in_text,
            ),
            (
                |t| matches!(t, IdentifierType::IndiaAadhaar),
                GovernmentIdentifierBuilder::find_india_aadhaars_in_text,
            ),
            (
                |t| matches!(t, IdentifierType::IndiaPan),
                GovernmentIdentifierBuilder::find_india_pans_in_text,
            ),
            (
                |t| matches!(t, IdentifierType::IndiaGstin),
                GovernmentIdentifierBuilder::find_india_gstins_in_text,
            ),
            (
                |t| matches!(t, IdentifierType::IndiaVehicleReg),
                GovernmentIdentifierBuilder::find_india_vehicle_registrations_in_text,
            ),
            (
                |t| matches!(t, IdentifierType::IndiaVoterId),
                GovernmentIdentifierBuilder::find_india_voter_ids_in_text,
            ),
            (
                |t| matches!(t, IdentifierType::IndiaPassport),
                GovernmentIdentifierBuilder::find_india_passports_in_text,
            ),
            (
                |t| matches!(t, IdentifierType::BrazilCpf),
                GovernmentIdentifierBuilder::find_brazil_cpfs_in_text,
            ),
            (
                |t| matches!(t, IdentifierType::BrazilCnpj),
                GovernmentIdentifierBuilder::find_brazil_cnpjs_in_text,
            ),
            (
                |t| matches!(t, IdentifierType::MexicoCurp),
                GovernmentIdentifierBuilder::find_mexico_curps_in_text,
            ),
            (
                |t| matches!(t, IdentifierType::NigeriaNin),
                GovernmentIdentifierBuilder::find_nigeria_nins_in_text,
            ),
            (
                |t| matches!(t, IdentifierType::ThailandTnin),
                GovernmentIdentifierBuilder::find_thailand_tnins_in_text,
            ),
            (
                |t| matches!(t, IdentifierType::FinlandHetu),
                GovernmentIdentifierBuilder::find_finland_hetus_in_text,
            ),
            (
                |t| matches!(t, IdentifierType::PolandPesel),
                GovernmentIdentifierBuilder::find_poland_pesels_in_text,
            ),
            (
                |t| matches!(t, IdentifierType::ItalyFiscalCode),
                GovernmentIdentifierBuilder::find_italy_fiscal_codes_in_text,
            ),
            (
                |t| matches!(t, IdentifierType::ItalyVat),
                GovernmentIdentifierBuilder::find_italy_vats_in_text,
            ),
            (
                |t| matches!(t, IdentifierType::ItalyPassport),
                GovernmentIdentifierBuilder::find_italy_passports_in_text,
            ),
            (
                |t| matches!(t, IdentifierType::ItalyIdentityCard),
                GovernmentIdentifierBuilder::find_italy_identity_cards_in_text,
            ),
            (
                |t| matches!(t, IdentifierType::ItalyDriverLicense),
                GovernmentIdentifierBuilder::find_italy_driver_licenses_in_text,
            ),
            (
                |t| matches!(t, IdentifierType::SingaporeNric),
                GovernmentIdentifierBuilder::find_singapore_nrics_in_text,
            ),
            (
                |t| matches!(t, IdentifierType::SpainNif),
                GovernmentIdentifierBuilder::find_spain_nifs_in_text,
            ),
            (
                |t| matches!(t, IdentifierType::SpainNie),
                GovernmentIdentifierBuilder::find_spain_nies_in_text,
            ),
            (
                |t| matches!(t, IdentifierType::UkNi),
                GovernmentIdentifierBuilder::find_uk_nis_in_text,
            ),
            (
                |t| matches!(t, IdentifierType::SwedenPersonnummer),
                GovernmentIdentifierBuilder::find_sweden_personnummers_in_text,
            ),
            (
                |t| matches!(t, IdentifierType::SwedenOrgnummer),
                GovernmentIdentifierBuilder::find_sweden_orgnummers_in_text,
            ),
            (
                |t| matches!(t, IdentifierType::VehicleId),
                GovernmentIdentifierBuilder::find_vehicle_ids_in_text,
            ),
        ];

        let finder = FINDERS
            .iter()
            .find(|(matches_variant, _)| matches_variant(id_type))?
            .1;
        let government = GovernmentIdentifierBuilder::new();
        Some(self.push_all(finder(&government, text)))
    }

    /// Handle domains whose builders expose a single `find_all_in_text` /
    /// `detect_all_in_text` entry point, plus the credential domain which
    /// requires context-based detection elsewhere.
    fn scan_grouped_type(&self, text: &str, id_type: &IdentifierType) -> Option<usize> {
        match id_type {
            IdentifierType::EmployeeId
            | IdentifierType::StudentId
            | IdentifierType::BadgeNumber => {
                let organizational = OrganizationalIdentifierBuilder::new();
                Some(self.push_matching(organizational.find_all_in_text(text), id_type))
            }
            IdentifierType::GPSCoordinate
            | IdentifierType::StreetAddress
            | IdentifierType::PostalCode => {
                let location = LocationIdentifierBuilder::new();
                Some(self.push_matching(location.find_all_in_text(text), id_type))
            }
            IdentifierType::MedicalRecordNumber
            | IdentifierType::HealthInsurance
            | IdentifierType::Prescription
            | IdentifierType::ProviderID
            | IdentifierType::MedicalCode
            | IdentifierType::MedicalLicense => {
                let medical = MedicalIdentifierBuilder::new();
                Some(self.push_matching(medical.find_all_in_text(text), id_type))
            }
            IdentifierType::Fingerprint
            | IdentifierType::FacialRecognition
            | IdentifierType::IrisScan
            | IdentifierType::VoicePrint
            | IdentifierType::DNASequence
            | IdentifierType::BiometricTemplate => {
                let biometric = BiometricIdentifierBuilder::new();
                Some(self.push_matching(biometric.detect_all_in_text(text), id_type))
            }
            // Credentials require context-based detection ("password:",
            // "pin="). Use CredentialIdentifierBuilder directly instead of
            // pattern-based scanning.
            IdentifierType::Password
            | IdentifierType::Pin
            | IdentifierType::SecurityAnswer
            | IdentifierType::Passphrase => Some(0),
            _ => None,
        }
    }

    /// Handle one-off variants that don't fit any domain grouping:
    /// connection strings (credentials), high-entropy strings, and explicit
    /// no-op variants (Unknown, unimplemented provider tokens).
    fn scan_special_type(&self, text: &str, id_type: &IdentifierType) -> Option<usize> {
        match id_type {
            IdentifierType::ConnectionString => {
                let creds = CredentialIdentifierBuilder::new();
                Some(usize::from(
                    creds.is_connection_string_with_credentials(text),
                ))
            }
            IdentifierType::HighEntropyString => {
                Some(self.push_all(entropy::detect_high_entropy_strings_in_text(text)))
            }
            // Not yet implemented in primitives.
            IdentifierType::GitHubToken
            | IdentifierType::GitLabToken
            | IdentifierType::AwsAccessKey
            | IdentifierType::AwsSessionToken
            | IdentifierType::Unknown => Some(0),
            _ => None,
        }
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
        let text = "Email: user@example.com, SSN: 517-29-8346";

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

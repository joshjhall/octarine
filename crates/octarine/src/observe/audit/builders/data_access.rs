//! Data access audit builder.
//!
//! Provides a fluent API for auditing data access events.

use crate::observe::audit::event::AuditEvent;
use crate::observe::audit::types::{AccessType, DataClassification, Outcome};
use crate::observe::compliance::{
    ComplianceTags, HipaaSafeguard, Iso27001Control, PciDssRequirement, Soc2Control,
};
use crate::observe::types::EventType;

/// Builder for data access audit events.
///
/// # Example
///
/// ```ignore
/// use octarine::observe::audit::Audit;
/// use octarine::observe::audit::DataClassification;
///
/// // Simple read
/// Audit::data_access()
///     .read("users_table")
///     .records(100)
///     .success()
///     .emit();
///
/// // Sensitive data access
/// Audit::data_access()
///     .read("medical_records")
///     .classification(DataClassification::Restricted)
///     .records(1)
///     .success()
///     .emit();
/// ```
#[derive(Debug, Clone)]
pub struct DataAccessAuditBuilder {
    access_type: AccessType,
    resource: String,
    record_count: Option<u64>,
    classification: Option<DataClassification>,
    query: Option<String>,
}

impl DataAccessAuditBuilder {
    /// Create a new data access audit builder for a read operation.
    pub fn read(resource: &str) -> Self {
        Self {
            access_type: AccessType::Read,
            resource: resource.to_string(),
            record_count: None,
            classification: None,
            query: None,
        }
    }

    /// Create a new data access audit builder for a create operation.
    pub fn create(resource: &str) -> Self {
        Self {
            access_type: AccessType::Create,
            resource: resource.to_string(),
            record_count: None,
            classification: None,
            query: None,
        }
    }

    /// Create a new data access audit builder for a write/update operation.
    pub fn write(resource: &str) -> Self {
        Self {
            access_type: AccessType::Write,
            resource: resource.to_string(),
            record_count: None,
            classification: None,
            query: None,
        }
    }

    /// Create a new data access audit builder for a delete operation.
    pub fn delete(resource: &str) -> Self {
        Self {
            access_type: AccessType::Delete,
            resource: resource.to_string(),
            record_count: None,
            classification: None,
            query: None,
        }
    }

    /// Create a new data access audit builder for an export operation.
    pub fn export(resource: &str) -> Self {
        Self {
            access_type: AccessType::Export,
            resource: resource.to_string(),
            record_count: None,
            classification: None,
            query: None,
        }
    }

    /// Create a new data access audit builder for a bulk operation.
    pub fn bulk(resource: &str) -> Self {
        Self {
            access_type: AccessType::Bulk,
            resource: resource.to_string(),
            record_count: None,
            classification: None,
            query: None,
        }
    }

    /// Set the number of records affected.
    #[must_use]
    pub fn records(mut self, count: u64) -> Self {
        self.record_count = Some(count);
        self
    }

    /// Set the data classification level.
    #[must_use]
    pub fn classification(mut self, classification: DataClassification) -> Self {
        self.classification = Some(classification);
        self
    }

    /// Set the query or operation details (e.g., SQL query, API endpoint).
    #[must_use]
    pub fn query(mut self, query: &str) -> Self {
        self.query = Some(query.to_string());
        self
    }

    /// Build a successful data access event.
    #[must_use]
    pub fn success(self) -> AuditEvent {
        self.build_event(Outcome::Success)
    }

    /// Build a failed data access event.
    #[must_use]
    pub fn failure(self, reason: &str) -> AuditEvent {
        self.build_event(Outcome::Failure(reason.to_string()))
    }

    /// Build a pending data access event.
    ///
    /// Use this for async operations where the result is not yet known.
    #[must_use]
    pub fn pending(self) -> AuditEvent {
        self.build_event(Outcome::Pending)
    }

    /// Build a data access event with unknown outcome.
    ///
    /// Use this when the operation result cannot be determined.
    #[must_use]
    pub fn unknown(self) -> AuditEvent {
        self.build_event(Outcome::Unknown)
    }

    fn build_event(self, outcome: Outcome) -> AuditEvent {
        let operation = format!("data.{}", self.access_type_str());

        let message = match &outcome {
            Outcome::Success => {
                let records_info = self
                    .record_count
                    .map(|c| format!(" ({} records)", c))
                    .unwrap_or_default();
                format!(
                    "{} {} on {}{}",
                    self.access_type_action(),
                    "succeeded",
                    self.resource,
                    records_info
                )
            }
            Outcome::Failure(reason) => {
                format!(
                    "{} {} on {}: {}",
                    self.access_type_action(),
                    "failed",
                    self.resource,
                    reason
                )
            }
            Outcome::Pending => {
                let records_info = self
                    .record_count
                    .map(|c| format!(" ({} records)", c))
                    .unwrap_or_default();
                format!(
                    "{} {} on {}{}",
                    self.access_type_action(),
                    "pending",
                    self.resource,
                    records_info
                )
            }
            Outcome::Unknown => {
                format!(
                    "{} {} on {}",
                    self.access_type_action(),
                    "outcome unknown",
                    self.resource
                )
            }
        };

        let event_type = match (&self.access_type, &outcome) {
            (AccessType::Create, Outcome::Success) => EventType::ResourceCreated,
            (AccessType::Write, Outcome::Success) => EventType::ResourceUpdated,
            (AccessType::Delete, Outcome::Success) => EventType::ResourceDeleted,
            (_, Outcome::Success) => EventType::Info,
            (_, Outcome::Failure(_)) => EventType::SystemError,
            (_, Outcome::Pending | Outcome::Unknown) => EventType::Info,
        };

        let mut event = AuditEvent::new(&operation, message, outcome, event_type)
            .with_metadata(
                "data.access_type",
                serde_json::json!(self.access_type_str()),
            )
            .with_metadata("data.resource", serde_json::json!(&self.resource));

        if let Some(count) = self.record_count {
            event = event.with_metadata("data.record_count", serde_json::json!(count));
        }

        if let Some(classification) = &self.classification {
            event = event.with_metadata(
                "data.classification",
                serde_json::json!(classification_str(classification)),
            );
        }

        if let Some(query) = &self.query {
            event = event.with_metadata("data.query", serde_json::json!(query));
        }

        // Apply compliance tags based on classification
        let mut tags = ComplianceTags::new()
            .with_soc2(Soc2Control::CC8_1) // Confidential information protection
            .with_iso27001(Iso27001Control::A8_3) // Information access restriction
            .with_iso27001(Iso27001Control::A8_15) // Logging
            .as_evidence();

        // Add HIPAA tags for restricted/confidential data
        if matches!(
            self.classification,
            Some(DataClassification::Restricted) | Some(DataClassification::Confidential)
        ) {
            tags = tags.with_hipaa(HipaaSafeguard::Technical);
        }

        // Add PCI-DSS for financial data exports
        if matches!(self.access_type, AccessType::Export) {
            tags = tags.with_pci_dss(PciDssRequirement::Req10);
        }

        event.with_compliance_tags(tags)
    }

    fn access_type_str(&self) -> &'static str {
        match self.access_type {
            AccessType::Read => "read",
            AccessType::Create => "create",
            AccessType::Write => "write",
            AccessType::Delete => "delete",
            AccessType::Export => "export",
            AccessType::Bulk => "bulk",
        }
    }

    fn access_type_action(&self) -> &'static str {
        match self.access_type {
            AccessType::Read => "Read",
            AccessType::Create => "Create",
            AccessType::Write => "Write",
            AccessType::Delete => "Delete",
            AccessType::Export => "Export",
            AccessType::Bulk => "Bulk operation",
        }
    }
}

fn classification_str(classification: &DataClassification) -> &'static str {
    match classification {
        DataClassification::Public => "public",
        DataClassification::Internal => "internal",
        DataClassification::Confidential => "confidential",
        DataClassification::Restricted => "restricted",
    }
}

impl Default for DataAccessAuditBuilder {
    fn default() -> Self {
        Self::read("")
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_success() {
        let event = DataAccessAuditBuilder::read("users").records(50).success();

        assert_eq!(event.operation(), "data.read");
        assert!(event.is_success());
        assert!(event.message().contains("50 records"));
    }

    #[test]
    fn test_write_failure() {
        let event = DataAccessAuditBuilder::write("orders").failure("Database timeout");

        assert_eq!(event.operation(), "data.write");
        assert!(!event.is_success());
        assert!(event.message().contains("Database timeout"));
    }

    #[test]
    fn test_delete_with_classification() {
        let event = DataAccessAuditBuilder::delete("audit_logs")
            .classification(DataClassification::Restricted)
            .records(10)
            .success();

        assert_eq!(event.operation(), "data.delete");
        assert_eq!(
            event.metadata.get("data.classification"),
            Some(&serde_json::json!("restricted"))
        );
    }

    #[test]
    fn test_export_with_query() {
        let event = DataAccessAuditBuilder::export("transactions")
            .query("SELECT * FROM transactions WHERE date > '2024-01-01'")
            .records(1000)
            .success();

        assert_eq!(event.operation(), "data.export");
        assert!(event.metadata.contains_key("data.query"));
    }

    #[test]
    fn test_compliance_tags_basic() {
        let event = DataAccessAuditBuilder::read("users").success();

        assert!(event.compliance_tags.soc2.contains(&Soc2Control::CC8_1));
        assert!(event.compliance_tags.is_evidence);
    }

    #[test]
    fn test_compliance_tags_restricted() {
        let event = DataAccessAuditBuilder::read("medical_records")
            .classification(DataClassification::Restricted)
            .success();

        assert!(
            event
                .compliance_tags
                .hipaa
                .contains(&HipaaSafeguard::Technical)
        );
    }

    #[test]
    fn test_compliance_tags_export() {
        let event = DataAccessAuditBuilder::export("payments").success();

        assert!(
            event
                .compliance_tags
                .pci_dss
                .contains(&PciDssRequirement::Req10)
        );
    }
}

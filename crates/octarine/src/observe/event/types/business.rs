//! Business logic audit events
//!
//! Track important business operations for audit trail.
//! These events are critical for compliance and business intelligence.

/// Business events for audit trail
#[derive(Debug, Clone)]
pub(super) enum BusinessEvent {
    /// Resource created
    ResourceCreated {
        resource_type: String,
        resource_id: String,
        created_by: String,
    },

    /// Resource updated
    ResourceUpdated {
        resource_type: String,
        resource_id: String,
        updated_by: String,
        changes: Vec<String>, // List of changed fields
    },

    /// Resource deleted
    ResourceDeleted {
        resource_type: String,
        resource_id: String,
        deleted_by: String,
        soft_delete: bool,
    },

    /// Data exported
    DataExported {
        export_type: String,
        record_count: usize,
        exported_by: String,
    },

    /// Data imported
    DataImported {
        import_type: String,
        record_count: usize,
        imported_by: String,
    },
}

//! Integration tests for audit builders
//!
//! These tests verify that the audit facade and builders correctly:
//! - Create AuditEvents with proper metadata
//! - Apply compliance tags based on domain
//! - Capture context (user_id, correlation_id, tenant_id)
//! - Handle success and failure outcomes

#![allow(clippy::panic, clippy::expect_used)]

use octarine::observe::audit::{
    Audit, ComplianceFramework, DataClassification, Outcome, ThreatLevel,
};
use octarine::observe::compliance::{HipaaSafeguard, Soc2Control};

// ============================================================================
// Authentication Builder Tests
// ============================================================================

#[test]
fn test_auth_login_success_metadata() {
    let event = Audit::auth().login("alice@example.com").success();

    assert_eq!(event.operation(), "auth.login");
    assert!(event.is_success());
    assert!(event.message().contains("alice@example.com"));
    assert!(event.message().contains("succeeded"));
}

#[test]
fn test_auth_login_failure_metadata() {
    let event = Audit::auth()
        .login("bob@example.com")
        .failure("Invalid password");

    assert_eq!(event.operation(), "auth.login");
    assert!(!event.is_success());
    assert!(event.message().contains("bob@example.com"));
    assert!(event.message().contains("Invalid password"));
}

#[test]
fn test_auth_with_mfa_provider() {
    let event = Audit::auth()
        .login("user@example.com")
        .with_mfa()
        .provider("totp")
        .success();

    assert!(event.is_success());
    // MFA and provider are in metadata (tested in unit tests)
}

#[test]
fn test_auth_logout() {
    let event = Audit::auth().logout("user@example.com").success();

    assert_eq!(event.operation(), "auth.logout");
    assert!(event.message().contains("Logout"));
}

#[test]
fn test_auth_password_change() {
    let event = Audit::auth().password_change("user@example.com").success();

    assert_eq!(event.operation(), "auth.password_change");
    assert!(event.message().contains("Password change"));
}

#[test]
fn test_auth_session_operations() {
    let create = Audit::auth().session_create("user@example.com").success();
    assert_eq!(create.operation(), "auth.session_create");

    let destroy = Audit::auth().session_destroy("user@example.com").success();
    assert_eq!(destroy.operation(), "auth.session_destroy");
}

#[test]
fn test_auth_compliance_tags() {
    let event = Audit::auth().login("test@example.com").success();

    // Auth events should have SOC2 CC6.1 and CC6.2
    assert!(event.compliance_tags().soc2.contains(&Soc2Control::CC6_1));
    assert!(event.compliance_tags().soc2.contains(&Soc2Control::CC6_2));
    // And HIPAA Technical
    assert!(
        event
            .compliance_tags()
            .hipaa
            .contains(&HipaaSafeguard::Technical)
    );
    // Marked as evidence
    assert!(event.compliance_tags().is_evidence);
}

// ============================================================================
// Data Access Builder Tests
// ============================================================================

#[test]
fn test_data_read_success() {
    let event = Audit::data_access()
        .read("users_table")
        .records(100)
        .success();

    assert_eq!(event.operation(), "data.read");
    assert!(event.is_success());
    assert!(event.message().contains("Read"));
    assert!(event.message().contains("users_table"));
    assert!(event.message().contains("100 records"));
}

#[test]
fn test_data_write_success() {
    let event = Audit::data_access()
        .write("orders_table")
        .records(5)
        .success();

    assert_eq!(event.operation(), "data.write");
    assert!(event.message().contains("Write"));
}

#[test]
fn test_data_delete_failure() {
    let event = Audit::data_access()
        .delete("audit_logs")
        .failure("Permission denied");

    assert_eq!(event.operation(), "data.delete");
    assert!(!event.is_success());
    assert!(event.message().contains("Permission denied"));
}

#[test]
fn test_data_export_with_query() {
    let event = Audit::data_access()
        .export("transactions")
        .query("SELECT * FROM transactions WHERE date > '2024-01-01'")
        .records(1000)
        .success();

    assert_eq!(event.operation(), "data.export");
}

#[test]
fn test_data_bulk_operation() {
    let event = Audit::data_access()
        .bulk("customers")
        .records(50000)
        .success();

    assert_eq!(event.operation(), "data.bulk");
}

#[test]
fn test_data_with_classification() {
    let event = Audit::data_access()
        .read("medical_records")
        .classification(DataClassification::Restricted)
        .records(1)
        .success();

    assert!(event.is_success());
}

#[test]
fn test_data_compliance_tags() {
    let event = Audit::data_access().read("users").success();

    // Data access should have SOC2 CC8.1
    assert!(event.compliance_tags().soc2.contains(&Soc2Control::CC8_1));
    assert!(event.compliance_tags().is_evidence);
}

#[test]
fn test_data_restricted_adds_hipaa() {
    let event = Audit::data_access()
        .read("phi_data")
        .classification(DataClassification::Restricted)
        .success();

    assert!(
        event
            .compliance_tags()
            .hipaa
            .contains(&HipaaSafeguard::Technical)
    );
}

// ============================================================================
// Admin Action Builder Tests
// ============================================================================

#[test]
fn test_admin_config_change() {
    let event = Audit::admin("config_change")
        .target("security.toml")
        .previous_value("debug=true")
        .new_value("debug=false")
        .success();

    assert_eq!(event.operation(), "admin.config_change");
    assert!(event.is_success());
    assert!(event.message().contains("config_change"));
}

#[test]
fn test_admin_with_justification() {
    let event = Audit::admin("user_suspension")
        .target("user:12345")
        .justification("Security policy violation - ticket SEC-2024-001")
        .success();

    assert!(event.is_success());
}

#[test]
fn test_admin_with_approver() {
    let event = Audit::admin("privilege_escalation")
        .target("user:dev@example.com")
        .approved_by("admin@example.com")
        .success();

    assert!(event.is_success());
}

#[test]
fn test_admin_compliance_tags() {
    let event = Audit::admin("role_assignment")
        .target("user:new-hire")
        .success();

    // Admin should have SOC2 CC6.3
    assert!(event.compliance_tags().soc2.contains(&Soc2Control::CC6_3));
    // And CC3.1 for admin actions
    assert!(event.compliance_tags().soc2.contains(&Soc2Control::CC3_1));
}

// ============================================================================
// Security Event Builder Tests
// ============================================================================

#[test]
fn test_security_threat_detected() {
    let event = Audit::security("intrusion_attempt")
        .threat_level(ThreatLevel::Critical)
        .source_ip("203.0.113.50")
        .attack_type("sql_injection")
        .failure("SQL injection detected in login form");

    assert_eq!(event.operation(), "security.intrusion_attempt");
    assert!(!event.is_success());
    assert!(event.message().contains("[critical]"));
}

#[test]
fn test_security_threat_blocked() {
    let event = Audit::security("rate_limit_applied")
        .source_ip("192.0.2.1")
        .blocked()
        .success();

    assert!(event.is_success());
    assert!(event.message().contains("blocked"));
}

#[test]
fn test_security_with_affected_resource() {
    let event = Audit::security("unauthorized_access")
        .threat_level(ThreatLevel::High)
        .affected_resource("/api/admin/users")
        .failure("Unauthorized API access attempt");

    assert!(!event.is_success());
}

#[test]
fn test_security_threat_levels() {
    let low = Audit::security("scan")
        .threat_level(ThreatLevel::Low)
        .success();
    let medium = Audit::security("anomaly")
        .threat_level(ThreatLevel::Medium)
        .success();
    let high = Audit::security("attack")
        .threat_level(ThreatLevel::High)
        .success();
    let critical = Audit::security("breach")
        .threat_level(ThreatLevel::Critical)
        .success();

    assert!(low.message().contains("[low]"));
    assert!(medium.message().contains("[medium]"));
    assert!(high.message().contains("[high]"));
    assert!(critical.message().contains("[critical]"));
}

#[test]
fn test_security_compliance_tags() {
    let event = Audit::security("test").success();

    // Security events should have CC6.6 and CC7.2
    assert!(event.compliance_tags().soc2.contains(&Soc2Control::CC6_6));
    assert!(event.compliance_tags().soc2.contains(&Soc2Control::CC7_2));
}

#[test]
fn test_security_high_threat_adds_cc71() {
    let event = Audit::security("test")
        .threat_level(ThreatLevel::High)
        .success();

    // High threats add CC7.1
    assert!(event.compliance_tags().soc2.contains(&Soc2Control::CC7_1));
}

// ============================================================================
// Compliance Check Builder Tests
// ============================================================================

#[test]
fn test_compliance_soc2_passed() {
    let event = Audit::compliance(ComplianceFramework::Soc2)
        .control("CC6.1")
        .evidence("access_review")
        .passed();

    assert_eq!(event.operation(), "compliance.soc2");
    assert!(event.is_success());
    assert!(event.message().contains("SOC2"));
    assert!(event.message().contains("CC6.1"));
    assert!(event.message().contains("passed"));
}

#[test]
fn test_compliance_hipaa_failed() {
    let event = Audit::compliance(ComplianceFramework::Hipaa)
        .control("164.312(a)(1)")
        .evidence("encryption_check")
        .failed("Missing encryption on PHI storage");

    assert!(!event.is_success());
    assert!(event.message().contains("HIPAA"));
    assert!(event.message().contains("failed"));
    assert!(event.message().contains("Missing encryption"));
}

#[test]
fn test_compliance_not_applicable() {
    let event = Audit::compliance(ComplianceFramework::PciDss)
        .control("Req 3.4")
        .not_applicable("No cardholder data stored");

    // N/A is considered a success
    assert!(event.is_success());
    assert!(event.message().contains("not applicable"));
}

#[test]
fn test_compliance_with_description() {
    let event = Audit::compliance(ComplianceFramework::Gdpr)
        .control("Art. 32")
        .description("Annual security assessment")
        .passed();

    assert!(event.is_success());
}

#[test]
fn test_compliance_frameworks() {
    let soc2 = Audit::compliance(ComplianceFramework::Soc2)
        .control("CC6.1")
        .passed();
    assert!(soc2.message().contains("SOC2"));

    let hipaa = Audit::compliance(ComplianceFramework::Hipaa)
        .control("164.312")
        .passed();
    assert!(hipaa.message().contains("HIPAA"));

    let gdpr = Audit::compliance(ComplianceFramework::Gdpr)
        .control("Art. 6")
        .passed();
    assert!(gdpr.message().contains("GDPR"));

    let pci = Audit::compliance(ComplianceFramework::PciDss)
        .control("Req 8.3")
        .passed();
    assert!(pci.message().contains("PCI_DSS"));

    let iso = Audit::compliance(ComplianceFramework::Iso27001)
        .control("A.5.1")
        .passed();
    assert!(iso.message().contains("ISO27001"));
}

#[test]
fn test_compliance_soc2_tags() {
    let event = Audit::compliance(ComplianceFramework::Soc2)
        .control("CC6.1")
        .passed();

    assert!(event.compliance_tags().soc2.contains(&Soc2Control::CC5_1));
    assert!(event.compliance_tags().is_evidence);
}

#[test]
fn test_compliance_hipaa_tags() {
    let event = Audit::compliance(ComplianceFramework::Hipaa)
        .control("164.312")
        .passed();

    assert!(
        event
            .compliance_tags()
            .hipaa
            .contains(&HipaaSafeguard::Technical)
    );
    assert!(
        event
            .compliance_tags()
            .hipaa
            .contains(&HipaaSafeguard::Administrative)
    );
}

// ============================================================================
// Outcome Tests
// ============================================================================

#[test]
fn test_outcome_success() {
    let outcome = Outcome::Success;
    assert!(outcome.is_success());
    assert!(!outcome.is_failure());
    assert!(outcome.failure_reason().is_none());
}

#[test]
fn test_outcome_failure() {
    let outcome = Outcome::Failure("Something went wrong".to_string());
    assert!(!outcome.is_success());
    assert!(outcome.is_failure());
    assert_eq!(outcome.failure_reason(), Some("Something went wrong"));
}

// ============================================================================
// Integration: Full Audit Flow
// ============================================================================

#[test]
fn test_complete_auth_flow() {
    // Simulate a complete authentication flow
    let login_attempt = Audit::auth()
        .login("user@example.com")
        .failure("Invalid password");
    assert!(!login_attempt.is_success());

    let login_success = Audit::auth()
        .login("user@example.com")
        .with_mfa()
        .provider("totp")
        .success();
    assert!(login_success.is_success());

    let session = Audit::auth().session_create("user@example.com").success();
    assert!(session.is_success());

    let logout = Audit::auth().logout("user@example.com").success();
    assert!(logout.is_success());
}

#[test]
fn test_complete_data_access_flow() {
    // Simulate a data access scenario
    let read = Audit::data_access()
        .read("customers")
        .classification(DataClassification::Internal)
        .records(100)
        .success();
    assert!(read.is_success());

    let write = Audit::data_access().write("customers").records(1).success();
    assert!(write.is_success());

    let export = Audit::data_access()
        .export("customers")
        .classification(DataClassification::Confidential)
        .query("SELECT * FROM customers WHERE region='US'")
        .records(500)
        .success();
    assert!(export.is_success());
}

#[test]
fn test_complete_security_incident_flow() {
    // Simulate a security incident detection and response
    let detected = Audit::security("suspicious_activity")
        .threat_level(ThreatLevel::Medium)
        .source_ip("192.0.2.100")
        .success();
    assert!(detected.is_success());

    let attack = Audit::security("sql_injection_attempt")
        .threat_level(ThreatLevel::High)
        .source_ip("192.0.2.100")
        .attack_type("sql_injection")
        .affected_resource("/api/login")
        .blocked()
        .failure("Attack blocked by WAF");
    assert!(!attack.is_success());

    let escalated = Audit::security("incident_escalated")
        .threat_level(ThreatLevel::Critical)
        .source_ip("192.0.2.100")
        .failure("Escalated to security team");
    assert!(!escalated.is_success());
}

#[test]
fn test_complete_compliance_audit_flow() {
    // Simulate a compliance audit
    let access_review = Audit::compliance(ComplianceFramework::Soc2)
        .control("CC6.1")
        .evidence("quarterly_access_review")
        .description("Q4 2024 access review")
        .passed();
    assert!(access_review.is_success());

    let encryption = Audit::compliance(ComplianceFramework::Hipaa)
        .control("164.312(a)(2)(iv)")
        .evidence("encryption_audit")
        .passed();
    assert!(encryption.is_success());

    let pci_na = Audit::compliance(ComplianceFramework::PciDss)
        .control("Req 3.4")
        .not_applicable("No cardholder data processed");
    assert!(pci_na.is_success());
}

//! Audit facade example
//!
//! Demonstrates the domain-specific audit builders for compliance-ready logging.
//!
//! Run with: `cargo run -p octarine --example observe_audit`

#![allow(clippy::print_stdout)]

use octarine::observe::audit::{
    Audit, ComplianceFramework, DataClassification, SecurityAction, ThreatLevel,
};

fn main() {
    println!("=== Octarine Audit Facade Demo ===\n");

    // ========================================================================
    // Authentication Auditing
    // ========================================================================
    println!("--- Authentication Events ---");

    // Successful login with MFA
    let login_event = Audit::auth()
        .login("alice@example.com")
        .with_mfa()
        .provider("totp")
        .success();

    println!(
        "Login: {} ({})",
        login_event.message(),
        if login_event.is_success() {
            "success"
        } else {
            "failure"
        }
    );

    // Failed login attempt
    let failed_login = Audit::auth()
        .login("bob@example.com")
        .failure("Invalid password");

    println!("Failed login: {}", failed_login.message());

    // Password change
    let pwd_change = Audit::auth().password_change("alice@example.com").success();

    println!("Password change: {}", pwd_change.message());

    // Session management
    let session = Audit::auth().session_create("alice@example.com").success();

    println!("Session: {}\n", session.message());

    // ========================================================================
    // Data Access Auditing
    // ========================================================================
    println!("--- Data Access Events ---");

    // Read operation with record count
    let read_event = Audit::data_access()
        .read("users_table")
        .records(50)
        .classification(DataClassification::Internal)
        .success();

    println!("Read: {}", read_event.message());

    // Write operation
    let write_event = Audit::data_access()
        .write("orders_table")
        .records(1)
        .success();

    println!("Write: {}", write_event.message());

    // Export with classification
    let export_event = Audit::data_access()
        .export("customer_data")
        .classification(DataClassification::Confidential)
        .query("SELECT * FROM customers WHERE region='US'")
        .records(1000)
        .success();

    println!("Export: {}", export_event.message());

    // Failed delete
    let delete_fail = Audit::data_access()
        .delete("audit_logs")
        .failure("Permission denied");

    println!("Delete failed: {}\n", delete_fail.message());

    // ========================================================================
    // Administrative Action Auditing
    // ========================================================================
    println!("--- Admin Action Events ---");

    // Configuration change with justification
    let config_change = Audit::admin("update_security_policy")
        .target("rate_limits.toml")
        .previous_value("100 req/min")
        .new_value("200 req/min")
        .justification("Increased limits for new feature launch")
        .approved_by("security-team@example.com")
        .success();

    println!("Config change: {}", config_change.message());

    // User management
    let user_suspend = Audit::admin("suspend_user")
        .target("user:malicious-actor@example.com")
        .justification("Detected suspicious activity - ticket SEC-2024-001")
        .success();

    println!("User suspend: {}", user_suspend.message());

    // Pending approval action
    let pending_action = Audit::admin("escalate_privileges")
        .target("user:developer@example.com")
        .justification("Needs production access for incident response")
        .pending();

    println!("Pending action: {}\n", pending_action.message());

    // ========================================================================
    // Security Event Auditing
    // ========================================================================
    println!("--- Security Events ---");

    // Threat detected and blocked
    let blocked_attack = Audit::security("sql_injection_attempt")
        .threat_level(ThreatLevel::High)
        .source_ip("203.0.113.50")
        .attack_type("sql_injection")
        .affected_resource("/api/login")
        .action(SecurityAction::Blocked)
        .failure("Attack blocked by WAF");

    println!("Blocked: {}", blocked_attack.message());

    // Using convenience method
    let rate_limited = Audit::security("rate_limit_exceeded")
        .source_ip("192.0.2.100")
        .blocked()
        .success();

    println!("Rate limited: {}", rate_limited.message());

    // Escalated incident
    let escalated = Audit::security("data_exfiltration_attempt")
        .threat_level(ThreatLevel::Critical)
        .source_ip("198.51.100.25")
        .escalated()
        .failure("Escalated to security team");

    println!("Escalated: {}", escalated.message());

    // Under investigation
    let investigating = Audit::security("anomalous_behavior")
        .threat_level(ThreatLevel::Medium)
        .source_ip("203.0.113.100")
        .pending();

    println!("Investigating: {}\n", investigating.message());

    // ========================================================================
    // Compliance Check Auditing
    // ========================================================================
    println!("--- Compliance Check Events ---");

    // SOC2 control passed
    let soc2_check = Audit::compliance(ComplianceFramework::Soc2)
        .control("CC6.1")
        .evidence("quarterly_access_review")
        .description("Q4 2024 Access Review")
        .passed();

    println!("SOC2: {}", soc2_check.message());

    // HIPAA check passed
    let hipaa_check = Audit::compliance(ComplianceFramework::Hipaa)
        .control("164.312(a)(2)(iv)")
        .evidence("encryption_audit")
        .passed();

    println!("HIPAA: {}", hipaa_check.message());

    // PCI-DSS not applicable
    let pci_na = Audit::compliance(ComplianceFramework::PciDss)
        .control("Req 3.4")
        .not_applicable("No cardholder data processed");

    println!("PCI-DSS: {}", pci_na.message());

    // GDPR check failed
    let gdpr_fail = Audit::compliance(ComplianceFramework::Gdpr)
        .control("Art. 17")
        .evidence("data_deletion_audit")
        .failed("Retention period exceeded for 12 records");

    println!("GDPR: {}", gdpr_fail.message());

    // ISO27001 in review
    let iso_review = Audit::compliance(ComplianceFramework::Iso27001)
        .control("A.5.1")
        .evidence("policy_review")
        .in_review();

    println!("ISO27001: {}", iso_review.message());

    // Indeterminate result
    let indeterminate = Audit::compliance(ComplianceFramework::Soc2)
        .control("CC7.1")
        .indeterminate("Evidence collection in progress");

    println!("Indeterminate: {}\n", indeterminate.message());

    // ========================================================================
    // Compliance Tags Inspection
    // ========================================================================
    println!("--- Compliance Tags ---");

    let auth_event = Audit::auth().login("test@example.com").success();
    println!(
        "Auth event has {} SOC2 controls, is_evidence: {}",
        auth_event.compliance_tags().soc2.len(),
        auth_event.compliance_tags().is_evidence
    );

    let security_event = Audit::security("test")
        .threat_level(ThreatLevel::High)
        .success();
    println!(
        "Security event has {} SOC2 controls, {} HIPAA safeguards",
        security_event.compliance_tags().soc2.len(),
        security_event.compliance_tags().hipaa.len()
    );

    println!("\n=== Demo Complete ===");
}

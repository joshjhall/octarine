#![allow(clippy::panic, clippy::expect_used)]

use octarine::auth::{MfaManager, generate_recovery_codes};

/// Full enrollment workflow: start → generate code → complete.
#[test]
fn test_enrollment_workflow() {
    let manager = MfaManager::new();

    // Start enrollment
    let enrollment = manager
        .start_enrollment("user@example.com")
        .expect("start enrollment");

    assert!(
        !enrollment.secret.as_base32().is_empty(),
        "Secret should not be empty"
    );
    assert!(
        !enrollment.otpauth_uri.is_empty(),
        "OTP auth URI should not be empty"
    );
    assert!(
        enrollment.otpauth_uri.contains("user"),
        "URI should contain account name"
    );
    assert!(
        !enrollment.recovery_codes.codes().is_empty(),
        "Should have recovery codes"
    );

    // Generate a valid code and complete enrollment
    let code = manager
        .generate_code(&enrollment.secret)
        .expect("generate code");
    let result = manager
        .complete_enrollment(code.as_str(), &enrollment.secret, "user1")
        .expect("complete enrollment");
    assert!(result, "Enrollment should succeed with valid code");
}

/// Invalid code fails enrollment.
#[test]
fn test_enrollment_with_invalid_code() {
    let manager = MfaManager::new();

    let enrollment = manager
        .start_enrollment("user@example.com")
        .expect("start enrollment");

    let result = manager
        .complete_enrollment("000000", &enrollment.secret, "user1")
        .expect("complete enrollment attempt");
    assert!(!result, "Invalid code should fail enrollment");
}

/// Verify code succeeds with correct code, fails with wrong code.
#[test]
fn test_code_verification() {
    let manager = MfaManager::new();

    let enrollment = manager
        .start_enrollment("user@example.com")
        .expect("start enrollment");

    // Generate and verify a valid code
    let code = manager
        .generate_code(&enrollment.secret)
        .expect("generate code");
    let valid = manager
        .validate_code(code.as_str(), &enrollment.secret, "user1")
        .expect("verify valid code");
    assert!(valid, "Valid code should verify");

    // Invalid code should fail
    let invalid = manager
        .validate_code("000000", &enrollment.secret, "user1")
        .expect("verify invalid code");
    assert!(!invalid, "Invalid code should not verify");
}

/// Recovery codes are single-use.
#[test]
fn test_recovery_code_single_use() {
    let manager = MfaManager::new();

    let enrollment = manager
        .start_enrollment("user@example.com")
        .expect("start enrollment");
    let mut codes = enrollment.recovery_codes;

    // Get first recovery code
    let first_code = codes
        .codes()
        .first()
        .expect("at least one code")
        .code()
        .to_string();

    // First use succeeds
    let used = manager.validate_recovery_code(&first_code, &mut codes, "user1");
    assert!(used, "First use of recovery code should succeed");

    // Second use fails
    let reused = manager.validate_recovery_code(&first_code, &mut codes, "user1");
    assert!(!reused, "Recovery code should not be reusable");
}

/// Regenerate recovery codes produces new set.
#[test]
fn test_regenerate_recovery_codes() {
    let manager = MfaManager::new();

    let codes1 = manager
        .regenerate_recovery_codes("user1")
        .expect("generate first set");
    let codes2 = manager
        .regenerate_recovery_codes("user1")
        .expect("generate second set");

    // New codes should be different from old ones
    let values1: Vec<_> = codes1
        .codes()
        .iter()
        .map(|c| c.code().to_string())
        .collect();
    let values2: Vec<_> = codes2
        .codes()
        .iter()
        .map(|c| c.code().to_string())
        .collect();

    assert_ne!(values1, values2, "Regenerated codes should be different");
}

/// generate_recovery_codes produces correct count and length.
#[test]
fn test_recovery_code_generation() {
    let codes = generate_recovery_codes(8, 10).expect("generate codes");

    assert_eq!(codes.codes().len(), 8, "Should have 8 codes");
    for code in codes.codes() {
        assert_eq!(code.code().len(), 10, "Each code should be 10 characters");
    }
}

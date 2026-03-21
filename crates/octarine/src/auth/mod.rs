//! Authentication module with OWASP ASVS compliance
//!
//! This module provides comprehensive authentication functionality following
//! OWASP Application Security Verification Standard (ASVS) V2 and V3 controls.
//!
//! # Features
//!
//! - **Password Policy** (V2.1): Configurable password requirements with zxcvbn strength checking
//! - **Session Management** (V3): Secure session handling with binding and timeouts
//! - **Account Lockout** (V2.2): Brute-force protection with exponential backoff
//! - **CSRF Protection** (V3.4): Token-based CSRF mitigation
//! - **Password Reset** (V2.5): Secure reset flow with rate limiting
//! - **Remember-Me** (V3.5): Secure persistent login tokens
//! - **Timing Safety** (V2.9.1): Account enumeration prevention via constant-time responses
//! - **TOTP/MFA** (V4.1): Time-based one-time passwords (auth-totp feature)
//! - **HIBP Integration** (V2.1.8): Breach checking via k-anonymity API (auth-hibp feature)
//!
//! # Architecture
//!
//! This is Layer 3 of the three-layer architecture:
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    auth/ (Public API)                       │
//! │  - AuthBuilder for unified configuration                    │
//! │  - Password, Session, Lockout managers                      │
//! │  - All operations emit observe events                       │
//! ├─────────────────────────────────────────────────────────────┤
//! │              primitives/auth/ (Internal)                    │
//! │  - Pure validation and generation functions                 │
//! │  - No logging, no side effects                              │
//! ├─────────────────────────────────────────────────────────────┤
//! │                    observe/ (Internal)                      │
//! │  - Logging, metrics, tracing                                │
//! │  - Audit trail for compliance                               │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Quick Start
//!
//! ```ignore
//! use octarine::auth::{PasswordPolicy, validate_password, estimate_strength};
//!
//! // Validate a password against default policy
//! let policy = PasswordPolicy::default();
//! match validate_password("MySecure#Password123!", &policy, Some("user@example.com")) {
//!     Ok(()) => println!("Password is valid"),
//!     Err(e) => println!("Password rejected: {}", e),
//! }
//!
//! // Check password strength
//! let strength = estimate_strength("MySecure#Password123!");
//! println!("Password strength: {:?}", strength);
//! ```
//!
//! # Feature Flags
//!
//! - `auth` - Base authentication (password policy, sessions, lockout)
//! - `auth-hibp` - HIBP breach checking via k-anonymity API
//! - `auth-totp` - TOTP/MFA support
//! - `auth-full` - All authentication features
//!
//! # ASVS Coverage
//!
//! | Control | Description | Status |
//! |---------|-------------|--------|
//! | V2.1.1 | Min password length >= 8 | ✅ |
//! | V2.1.2 | Max password length >= 64 | ✅ |
//! | V2.1.7 | Common password blocklist | ✅ (via zxcvbn) |
//! | V2.1.8 | Breached password check | ✅ (auth-hibp) |
//! | V2.2.1 | Rate limiting | ✅ |
//! | V2.2.2 | Account lockout | ✅ |
//! | V2.3.1 | Password history | ✅ |
//! | V2.4.1 | Argon2id hashing | ✅ (via crypto module) |
//! | V3.1.1 | Session ID 128+ bits | ✅ |
//! | V3.2.1 | Session binding | ✅ |
//! | V3.3.1 | Absolute timeout | ✅ |
//! | V3.3.2 | Idle timeout | ✅ |
//! | V3.3.3 | Logout termination | ✅ |
//! | V3.4.1 | CSRF token validation | ✅ |
//! | V2.5.1 | Reset tokens random 128+ bits | ✅ |
//! | V2.5.2 | Reset token expiration | ✅ |
//! | V2.5.4 | Reset rate limiting | ✅ |
//! | V3.5.1 | Remember-me token security | ✅ |
//! | V3.5.2 | Split selector:validator design | ✅ |
//! | V3.5.3 | Token rotation on use | ✅ |
//! | V2.9.1 | Account enumeration prevention | ✅ |
//! | V4.1.1 | TOTP support | ✅ (auth-totp) |

pub mod csrf;
pub mod lockout;
pub mod password;
pub mod remember;
pub mod reset;
pub mod session;
pub mod timing;

#[cfg(feature = "auth-totp")]
pub mod mfa;

// Coming in later phases:
// pub mod builder;
// pub mod middleware;

// Re-export CSRF types at auth level for convenience
pub use csrf::{
    CsrfConfig,
    CsrfConfigBuilder,
    CsrfProtection,
    CsrfToken,
    SameSite as CsrfSameSite, // Renamed to avoid collision with session::SameSite
};

// Re-export password types at auth level for convenience
pub use password::{
    PasswordPolicy, PasswordPolicyBuilder, PasswordStrength, estimate_strength, validate_password,
};

// Re-export session types at auth level for convenience
pub use session::{
    MemorySessionStore, SameSite, Session, SessionBinding, SessionConfig, SessionConfigBuilder,
    SessionId, SessionManager, SessionStore,
};

// Re-export lockout types at auth level for convenience
pub use lockout::{
    LockoutConfig, LockoutConfigBuilder, LockoutDecision, LockoutIdentifier, LockoutManager,
    LockoutStatus, LockoutStore, MemoryLockoutStore,
};

// Re-export HIBP types at auth level (requires auth-hibp feature)
#[cfg(feature = "auth-hibp")]
pub use password::{HibpClient, HibpConfig, HibpConfigBuilder, check_breach};

// Re-export reset types at auth level for convenience
pub use reset::{
    MemoryResetStore, ResetConfig, ResetConfigBuilder, ResetManager, ResetToken, ResetTokenStore,
};

// Re-export remember types at auth level for convenience
pub use remember::{
    MemoryRememberStore, RememberConfig, RememberConfigBuilder, RememberManager, RememberToken,
    RememberTokenPair, RememberTokenStore,
};

// Re-export timing types at auth level for convenience
pub use timing::{
    ConstantTimeConfig, ConstantTimeConfigBuilder, constant_time_response,
    constant_time_response_sync,
};

// Re-export MFA types at auth level (requires auth-totp feature)
#[cfg(feature = "auth-totp")]
pub use mfa::{
    MfaManager, RecoveryCode, RecoveryCodes, TotpAlgorithm, TotpConfig, TotpConfigBuilder,
    TotpSecret, generate_recovery_codes, generate_totp_secret, validate_totp_code,
};

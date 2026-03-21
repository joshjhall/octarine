//! Exit codes following Unix conventions
//!
//! Based on BSD sysexits.h and common Unix practices.

use std::process::Termination;

/// Standard exit codes for CLI applications
///
/// Follows BSD sysexits.h conventions where applicable.
///
/// # Example
///
/// ```ignore
/// use octarine::runtime::cli::ExitCode;
///
/// fn main() -> ExitCode {
///     if some_error {
///         return ExitCode::GENERAL_ERROR;
///     }
///     ExitCode::SUCCESS
/// }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExitCode(u8);

impl ExitCode {
    /// Successful termination (0)
    pub const SUCCESS: Self = Self(0);

    /// General error (1)
    pub const GENERAL_ERROR: Self = Self(1);

    /// Command line usage error (2)
    ///
    /// The command was used incorrectly (bad arguments, wrong number of
    /// arguments, etc.)
    pub const USAGE_ERROR: Self = Self(2);

    /// Data format error (65 - EX_DATAERR)
    ///
    /// The input data was incorrect in some way.
    pub const DATA_ERROR: Self = Self(65);

    /// Cannot open input (66 - EX_NOINPUT)
    ///
    /// An input file did not exist or was not readable.
    pub const NO_INPUT: Self = Self(66);

    /// User unknown (67 - EX_NOUSER)
    pub const NO_USER: Self = Self(67);

    /// Host unknown (68 - EX_NOHOST)
    pub const NO_HOST: Self = Self(68);

    /// Service unavailable (69 - EX_UNAVAILABLE)
    ///
    /// A service is unavailable (could be a network service or a local daemon).
    pub const UNAVAILABLE: Self = Self(69);

    /// Internal software error (70 - EX_SOFTWARE)
    ///
    /// An internal software error has been detected.
    pub const SOFTWARE_ERROR: Self = Self(70);

    /// System error (71 - EX_OSERR)
    ///
    /// An operating system error has been detected.
    pub const OS_ERROR: Self = Self(71);

    /// Critical OS file missing (72 - EX_OSFILE)
    pub const OS_FILE: Self = Self(72);

    /// Cannot create output file (73 - EX_CANTCREAT)
    pub const CANT_CREATE: Self = Self(73);

    /// I/O error (74 - EX_IOERR)
    pub const IO_ERROR: Self = Self(74);

    /// Temporary failure (75 - EX_TEMPFAIL)
    ///
    /// A temporary failure occurred. The user is invited to retry.
    pub const TEMP_FAILURE: Self = Self(75);

    /// Remote error in protocol (76 - EX_PROTOCOL)
    pub const PROTOCOL_ERROR: Self = Self(76);

    /// Permission denied (77 - EX_NOPERM)
    pub const NO_PERMISSION: Self = Self(77);

    /// Configuration error (78 - EX_CONFIG)
    pub const CONFIG_ERROR: Self = Self(78);

    /// User interrupted (130 - SIGINT + 128)
    pub const INTERRUPTED: Self = Self(130);

    /// Create a custom exit code
    ///
    /// # Example
    ///
    /// ```
    /// use octarine::runtime::cli::ExitCode;
    ///
    /// let code = ExitCode::new(42);
    /// assert_eq!(code.code(), 42);
    /// ```
    #[must_use]
    pub const fn new(code: u8) -> Self {
        Self(code)
    }

    /// Get the numeric exit code
    #[must_use]
    pub const fn code(self) -> u8 {
        self.0
    }

    /// Check if this is a success code (0)
    #[must_use]
    pub const fn is_success(self) -> bool {
        self.0 == 0
    }

    /// Check if this is an error code (non-zero)
    #[must_use]
    pub const fn is_error(self) -> bool {
        self.0 != 0
    }
}

impl Default for ExitCode {
    fn default() -> Self {
        Self::SUCCESS
    }
}

impl From<u8> for ExitCode {
    fn from(code: u8) -> Self {
        Self(code)
    }
}

impl From<ExitCode> for u8 {
    fn from(code: ExitCode) -> Self {
        code.0
    }
}

impl From<ExitCode> for i32 {
    fn from(code: ExitCode) -> Self {
        i32::from(code.0)
    }
}

impl From<ExitCode> for std::process::ExitCode {
    fn from(code: ExitCode) -> Self {
        std::process::ExitCode::from(code.0)
    }
}

impl Termination for ExitCode {
    fn report(self) -> std::process::ExitCode {
        std::process::ExitCode::from(self.0)
    }
}

impl std::fmt::Display for ExitCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn test_success() {
        assert!(ExitCode::SUCCESS.is_success());
        assert!(!ExitCode::SUCCESS.is_error());
        assert_eq!(ExitCode::SUCCESS.code(), 0);
    }

    #[test]
    fn test_error() {
        assert!(!ExitCode::GENERAL_ERROR.is_success());
        assert!(ExitCode::GENERAL_ERROR.is_error());
        assert_eq!(ExitCode::GENERAL_ERROR.code(), 1);
    }

    #[test]
    fn test_custom() {
        let code = ExitCode::new(42);
        assert_eq!(code.code(), 42);
        assert!(code.is_error());
    }

    #[test]
    fn test_conversions() {
        let code = ExitCode::new(5);
        assert_eq!(u8::from(code), 5);
        assert_eq!(i32::from(code), 5);
    }

    #[test]
    fn test_from_u8() {
        let code: ExitCode = 10.into();
        assert_eq!(code.code(), 10);
    }

    #[test]
    fn test_display() {
        assert_eq!(format!("{}", ExitCode::SUCCESS), "0");
        assert_eq!(format!("{}", ExitCode::GENERAL_ERROR), "1");
    }

    #[test]
    fn test_default() {
        assert_eq!(ExitCode::default(), ExitCode::SUCCESS);
    }

    #[test]
    fn test_sysexits_codes() {
        assert_eq!(ExitCode::DATA_ERROR.code(), 65);
        assert_eq!(ExitCode::NO_INPUT.code(), 66);
        assert_eq!(ExitCode::UNAVAILABLE.code(), 69);
        assert_eq!(ExitCode::SOFTWARE_ERROR.code(), 70);
        assert_eq!(ExitCode::IO_ERROR.code(), 74);
        assert_eq!(ExitCode::CONFIG_ERROR.code(), 78);
    }
}

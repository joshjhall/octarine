//! Network types shared across primitives
//!
//! Common network-related types used by both security validation
//! and identifier detection modules.

// ============================================================================
// Port Range
// ============================================================================

/// Port range specification
///
/// Used for both port classification (which range a port falls into)
/// and port validation (checking if a port is within an allowed range).
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::PortRange;
///
/// // Classification
/// let range = PortRange::classify(80);
/// assert_eq!(range, PortRange::WellKnown);
///
/// // Validation
/// assert!(PortRange::WellKnown.contains(80));
/// assert!(!PortRange::WellKnown.contains(8080));
///
/// // Custom ranges
/// let custom = PortRange::Custom { min: 8000, max: 9000 };
/// assert!(custom.contains(8080));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PortRange {
    /// All valid ports (1-65535)
    #[default]
    All,
    /// Well-known ports (0-1023) - require root/admin
    WellKnown,
    /// Registered ports (1024-49151)
    Registered,
    /// Dynamic/private ports (49152-65535)
    Dynamic,
    /// User-defined range
    Custom { min: u16, max: u16 },
}

impl PortRange {
    /// Classify a port number into its range
    ///
    /// Returns the standard range classification (WellKnown, Registered, or Dynamic).
    #[must_use]
    pub fn classify(port: u16) -> Self {
        match port {
            0..=1023 => Self::WellKnown,
            1024..=49151 => Self::Registered,
            49152..=65535 => Self::Dynamic,
        }
    }

    /// Check if a port is within this range
    #[must_use]
    pub fn contains(&self, port: u16) -> bool {
        match self {
            Self::All => port >= 1,
            Self::WellKnown => port <= 1023,
            Self::Registered => (1024..=49151).contains(&port),
            Self::Dynamic => port >= 49152,
            Self::Custom { min, max } => (*min..=*max).contains(&port),
        }
    }

    /// Get the minimum port in this range
    #[must_use]
    pub fn min(&self) -> u16 {
        match self {
            Self::All => 1,
            Self::WellKnown => 0,
            Self::Registered => 1024,
            Self::Dynamic => 49152,
            Self::Custom { min, .. } => *min,
        }
    }

    /// Get the maximum port in this range
    #[must_use]
    pub fn max(&self) -> u16 {
        match self {
            Self::All => 65535,
            Self::WellKnown => 1023,
            Self::Registered => 49151,
            Self::Dynamic => 65535,
            Self::Custom { max, .. } => *max,
        }
    }

    /// Check if this is a privileged range (requires root/admin)
    #[must_use]
    pub fn is_privileged(&self) -> bool {
        matches!(self, Self::WellKnown)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify() {
        assert_eq!(PortRange::classify(0), PortRange::WellKnown);
        assert_eq!(PortRange::classify(80), PortRange::WellKnown);
        assert_eq!(PortRange::classify(1023), PortRange::WellKnown);
        assert_eq!(PortRange::classify(1024), PortRange::Registered);
        assert_eq!(PortRange::classify(8080), PortRange::Registered);
        assert_eq!(PortRange::classify(49151), PortRange::Registered);
        assert_eq!(PortRange::classify(49152), PortRange::Dynamic);
        assert_eq!(PortRange::classify(65535), PortRange::Dynamic);
    }

    #[test]
    fn test_contains() {
        // All
        assert!(PortRange::All.contains(1));
        assert!(PortRange::All.contains(65535));
        assert!(!PortRange::All.contains(0));

        // WellKnown
        assert!(PortRange::WellKnown.contains(0));
        assert!(PortRange::WellKnown.contains(80));
        assert!(PortRange::WellKnown.contains(1023));
        assert!(!PortRange::WellKnown.contains(1024));

        // Registered
        assert!(PortRange::Registered.contains(1024));
        assert!(PortRange::Registered.contains(8080));
        assert!(PortRange::Registered.contains(49151));
        assert!(!PortRange::Registered.contains(1023));
        assert!(!PortRange::Registered.contains(49152));

        // Dynamic
        assert!(PortRange::Dynamic.contains(49152));
        assert!(PortRange::Dynamic.contains(65535));
        assert!(!PortRange::Dynamic.contains(49151));

        // Custom
        let custom = PortRange::Custom {
            min: 8000,
            max: 9000,
        };
        assert!(custom.contains(8000));
        assert!(custom.contains(8080));
        assert!(custom.contains(9000));
        assert!(!custom.contains(7999));
        assert!(!custom.contains(9001));
    }

    #[test]
    fn test_min_max() {
        assert_eq!(PortRange::All.min(), 1);
        assert_eq!(PortRange::All.max(), 65535);

        assert_eq!(PortRange::WellKnown.min(), 0);
        assert_eq!(PortRange::WellKnown.max(), 1023);

        assert_eq!(PortRange::Registered.min(), 1024);
        assert_eq!(PortRange::Registered.max(), 49151);

        assert_eq!(PortRange::Dynamic.min(), 49152);
        assert_eq!(PortRange::Dynamic.max(), 65535);

        let custom = PortRange::Custom {
            min: 8000,
            max: 9000,
        };
        assert_eq!(custom.min(), 8000);
        assert_eq!(custom.max(), 9000);
    }

    #[test]
    fn test_is_privileged() {
        assert!(PortRange::WellKnown.is_privileged());
        assert!(!PortRange::All.is_privileged());
        assert!(!PortRange::Registered.is_privileged());
        assert!(!PortRange::Dynamic.is_privileged());
    }
}

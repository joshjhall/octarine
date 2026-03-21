//! Constants for filename detection
//!
//! Defines common character sets and name lists used for security detection.

// ============================================================================
// Constants
// ============================================================================

/// Characters dangerous in shell contexts
pub const DANGEROUS_SHELL_CHARS: &[char] = &[
    ';', '|', '&', '$', '`', '(', ')', '{', '}', '<', '>', '!', '\\', '"', '\'', '*', '?', '[',
    ']', '#', '~', '\n', '\r',
];

/// Characters reserved in Windows filenames
pub const RESERVED_WINDOWS_CHARS: &[char] = &['<', '>', ':', '"', '|', '?', '*'];

/// Windows reserved device names (case-insensitive)
pub const RESERVED_WINDOWS_NAMES: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

/// Common dangerous extensions
pub const DANGEROUS_EXTENSIONS: &[&str] = &[
    "exe", "bat", "cmd", "com", "msi", "scr", "pif", "vbs", "vbe", "js", "jse", "ws", "wsf", "wsc",
    "wsh", "ps1", "ps1xml", "ps2", "ps2xml", "psc1", "psc2", "msh", "msh1", "msh2", "mshxml",
    "msh1xml", "msh2xml", "scf", "lnk", "inf", "reg", "dll", "cpl", "hta", "jar",
];

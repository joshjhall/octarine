//! Output formatting and styling for CLI applications

use std::io::{self, Write};

/// Output format for CLI results
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OutputFormat {
    /// Human-readable text output
    #[default]
    Text,
    /// JSON output for machine consumption
    Json,
    /// Quiet mode - minimal output
    Quiet,
}

impl OutputFormat {
    /// Parse from string (for argument parsing)
    #[must_use]
    pub fn from_str_opt(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "text" | "human" => Some(Self::Text),
            "json" => Some(Self::Json),
            "quiet" | "silent" => Some(Self::Quiet),
            _ => None,
        }
    }
}

impl std::str::FromStr for OutputFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_str_opt(s)
            .ok_or_else(|| format!("Unknown format '{}'. Use: text, json, or quiet", s))
    }
}

/// Output styling options
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutputStyle {
    /// Whether to use colors
    pub color: bool,
    /// Whether to use Unicode symbols
    pub unicode: bool,
    /// Whether output is going to a terminal
    pub is_tty: bool,
}

impl OutputStyle {
    /// Create style for terminal output
    #[must_use]
    pub fn terminal() -> Self {
        Self {
            color: true,
            unicode: true,
            is_tty: true,
        }
    }

    /// Create style for non-terminal (pipe/file) output
    #[must_use]
    pub fn plain() -> Self {
        Self {
            color: false,
            unicode: false,
            is_tty: false,
        }
    }

    /// Detect style based on environment
    #[must_use]
    pub fn detect() -> Self {
        #[cfg(feature = "console")]
        {
            let term = console::Term::stdout();
            Self {
                color: term.is_term() && std::env::var("NO_COLOR").is_err(),
                unicode: term.is_term(),
                is_tty: term.is_term(),
            }
        }
        #[cfg(not(feature = "console"))]
        {
            Self::plain()
        }
    }

    /// Success symbol
    #[must_use]
    pub fn success_symbol(&self) -> &'static str {
        if self.unicode { "✓" } else { "[OK]" }
    }

    /// Error symbol
    #[must_use]
    pub fn error_symbol(&self) -> &'static str {
        if self.unicode { "✗" } else { "[ERROR]" }
    }

    /// Warning symbol
    #[must_use]
    pub fn warning_symbol(&self) -> &'static str {
        if self.unicode { "⚠" } else { "[WARN]" }
    }

    /// Info symbol
    #[must_use]
    pub fn info_symbol(&self) -> &'static str {
        if self.unicode { "ℹ" } else { "[INFO]" }
    }

    /// Arrow/pointer symbol
    #[must_use]
    pub fn arrow_symbol(&self) -> &'static str {
        if self.unicode { "→" } else { "->" }
    }

    /// Bullet point symbol
    #[must_use]
    pub fn bullet_symbol(&self) -> &'static str {
        if self.unicode { "•" } else { "*" }
    }
}

impl Default for OutputStyle {
    fn default() -> Self {
        Self::detect()
    }
}

/// Helper for styled console output
#[derive(Debug)]
pub struct StyledOutput {
    style: OutputStyle,
}

impl StyledOutput {
    /// Create a new styled output helper
    #[must_use]
    pub fn new(style: OutputStyle) -> Self {
        Self { style }
    }

    /// Create with auto-detected style
    #[must_use]
    pub fn auto() -> Self {
        Self::new(OutputStyle::detect())
    }

    /// Get the current style
    #[must_use]
    pub fn style(&self) -> &OutputStyle {
        &self.style
    }

    /// Print a success message
    pub fn success(&self, message: &str) -> io::Result<()> {
        self.print_styled("green", self.style.success_symbol(), message)
    }

    /// Print an error message
    pub fn error(&self, message: &str) -> io::Result<()> {
        self.print_styled("red", self.style.error_symbol(), message)
    }

    /// Print a warning message
    pub fn warning(&self, message: &str) -> io::Result<()> {
        self.print_styled("yellow", self.style.warning_symbol(), message)
    }

    /// Print an info message
    pub fn info(&self, message: &str) -> io::Result<()> {
        self.print_styled("blue", self.style.info_symbol(), message)
    }

    /// Print a plain message (no prefix)
    pub fn print(&self, message: &str) -> io::Result<()> {
        let stdout = io::stdout();
        let mut handle = stdout.lock();
        writeln!(handle, "{}", message)
    }

    /// Print without newline
    pub fn print_inline(&self, message: &str) -> io::Result<()> {
        let stdout = io::stdout();
        let mut handle = stdout.lock();
        write!(handle, "{}", message)?;
        handle.flush()
    }

    /// Print a styled message with prefix
    #[cfg(feature = "console")]
    fn print_styled(&self, color: &str, prefix: &str, message: &str) -> io::Result<()> {
        use console::style;

        let stdout = io::stdout();
        let mut handle = stdout.lock();

        if self.style.color {
            let styled_prefix = match color {
                "green" => style(prefix).green().bold(),
                "red" => style(prefix).red().bold(),
                "yellow" => style(prefix).yellow().bold(),
                "blue" => style(prefix).blue().bold(),
                "cyan" => style(prefix).cyan().bold(),
                _ => style(prefix).bold(),
            };
            writeln!(handle, "{} {}", styled_prefix, message)
        } else {
            writeln!(handle, "{} {}", prefix, message)
        }
    }

    /// Print a styled message with prefix (fallback without console)
    #[cfg(not(feature = "console"))]
    fn print_styled(&self, _color: &str, prefix: &str, message: &str) -> io::Result<()> {
        let stdout = io::stdout();
        let mut handle = stdout.lock();
        writeln!(handle, "{} {}", prefix, message)
    }

    /// Print a header/title
    #[cfg(feature = "console")]
    pub fn header(&self, title: &str) -> io::Result<()> {
        use console::style;

        let stdout = io::stdout();
        let mut handle = stdout.lock();

        if self.style.color {
            writeln!(handle, "\n{}", style(title).bold().underlined())
        } else {
            writeln!(handle, "\n{}\n{}", title, "=".repeat(title.len()))
        }
    }

    /// Print a header/title (fallback without console)
    #[cfg(not(feature = "console"))]
    pub fn header(&self, title: &str) -> io::Result<()> {
        let stdout = io::stdout();
        let mut handle = stdout.lock();
        writeln!(handle, "\n{}\n{}", title, "=".repeat(title.len()))
    }

    /// Print a list item
    pub fn list_item(&self, item: &str) -> io::Result<()> {
        let stdout = io::stdout();
        let mut handle = stdout.lock();
        writeln!(handle, "  {} {}", self.style.bullet_symbol(), item)
    }

    /// Print a key-value pair
    #[cfg(feature = "console")]
    pub fn key_value(&self, key: &str, value: &str) -> io::Result<()> {
        use console::style;

        let stdout = io::stdout();
        let mut handle = stdout.lock();

        if self.style.color {
            writeln!(handle, "  {}: {}", style(key).cyan(), value)
        } else {
            writeln!(handle, "  {}: {}", key, value)
        }
    }

    /// Print a key-value pair (fallback without console)
    #[cfg(not(feature = "console"))]
    pub fn key_value(&self, key: &str, value: &str) -> io::Result<()> {
        let stdout = io::stdout();
        let mut handle = stdout.lock();
        writeln!(handle, "  {}: {}", key, value)
    }
}

impl Default for StyledOutput {
    fn default() -> Self {
        Self::auto()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn test_output_format_parse() {
        assert_eq!(OutputFormat::from_str_opt("text"), Some(OutputFormat::Text));
        assert_eq!(OutputFormat::from_str_opt("json"), Some(OutputFormat::Json));
        assert_eq!(
            OutputFormat::from_str_opt("quiet"),
            Some(OutputFormat::Quiet)
        );
        assert_eq!(OutputFormat::from_str_opt("unknown"), None);
    }

    #[test]
    fn test_output_format_from_str() {
        assert_eq!("text".parse::<OutputFormat>().unwrap(), OutputFormat::Text);
        assert_eq!("JSON".parse::<OutputFormat>().unwrap(), OutputFormat::Json);
        assert!("invalid".parse::<OutputFormat>().is_err());
    }

    #[test]
    fn test_output_style_terminal() {
        let style = OutputStyle::terminal();
        assert!(style.color);
        assert!(style.unicode);
        assert!(style.is_tty);
    }

    #[test]
    fn test_output_style_plain() {
        let style = OutputStyle::plain();
        assert!(!style.color);
        assert!(!style.unicode);
        assert!(!style.is_tty);
    }

    #[test]
    fn test_symbols_unicode() {
        let style = OutputStyle::terminal();
        assert_eq!(style.success_symbol(), "✓");
        assert_eq!(style.error_symbol(), "✗");
        assert_eq!(style.warning_symbol(), "⚠");
        assert_eq!(style.info_symbol(), "ℹ");
    }

    #[test]
    fn test_symbols_ascii() {
        let style = OutputStyle::plain();
        assert_eq!(style.success_symbol(), "[OK]");
        assert_eq!(style.error_symbol(), "[ERROR]");
        assert_eq!(style.warning_symbol(), "[WARN]");
        assert_eq!(style.info_symbol(), "[INFO]");
    }

    #[test]
    fn test_styled_output_creation() {
        let output = StyledOutput::new(OutputStyle::plain());
        assert!(!output.style().color);
    }
}

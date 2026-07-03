//! Interactive prompts for CLI applications
//!
//! Provides user input, confirmation, selection, and password prompts.

use std::io::{self, BufRead, Write};

use super::{CliError, CliResult};

/// Text input prompt
///
/// # Example
///
/// Pre-existing example - ignored at compile until adapted.
/// ```ignore
/// use octarine::runtime::cli::Input;
///
/// let name = Input::new("What is your name?")
///     .default("Anonymous")
///     .prompt()?;
/// ```
pub struct Input {
    message: String,
    default: Option<String>,
    allow_empty: bool,
}

impl Input {
    /// Create a new input prompt
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            default: None,
            allow_empty: false,
        }
    }

    /// Set a default value
    #[must_use]
    pub fn default(mut self, value: impl Into<String>) -> Self {
        self.default = Some(value.into());
        self
    }

    /// Allow empty input
    #[must_use]
    pub fn allow_empty(mut self) -> Self {
        self.allow_empty = true;
        self
    }

    /// Show the prompt and get user input
    pub fn prompt(self) -> CliResult<String> {
        let stdout = io::stdout();
        let stdin = io::stdin();
        let mut writer = stdout.lock();
        let mut reader = stdin.lock();
        self.prompt_with(&mut reader, &mut writer)
    }

    /// Render the prompt to `writer` and parse a line from `reader`.
    ///
    /// Factored out of [`Input::prompt`] so the parse/validation branches can
    /// be driven with in-memory readers in tests. The public `prompt()` wires
    /// this to the process stdin/stdout locks.
    fn prompt_with<R: BufRead, W: Write>(
        self,
        reader: &mut R,
        writer: &mut W,
    ) -> CliResult<String> {
        // Print prompt
        if let Some(ref default) = self.default {
            write!(writer, "{} [{}]: ", self.message, default)
                .map_err(|e| CliError::io(e.to_string()))?;
        } else {
            write!(writer, "{}: ", self.message).map_err(|e| CliError::io(e.to_string()))?;
        }
        writer.flush().map_err(|e| CliError::io(e.to_string()))?;

        // Read input
        let mut input = String::new();
        reader
            .read_line(&mut input)
            .map_err(|e| CliError::io(e.to_string()))?;

        let input = input.trim().to_string();

        // Handle empty input
        if input.is_empty() {
            if let Some(default) = self.default {
                return Ok(default);
            }
            if !self.allow_empty {
                return Err(CliError::usage("Input cannot be empty"));
            }
        }

        Ok(input)
    }
}

/// Confirmation prompt (yes/no)
///
/// # Example
///
/// Pre-existing example - ignored at compile until adapted.
/// ```ignore
/// use octarine::runtime::cli::Confirm;
///
/// if Confirm::new("Delete all files?")
///     .default(false)
///     .prompt()?
/// {
///     // Delete files
/// }
/// ```
pub struct Confirm {
    message: String,
    default: Option<bool>,
}

impl Confirm {
    /// Create a new confirmation prompt
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            default: None,
        }
    }

    /// Set the default value
    #[must_use]
    pub fn default(mut self, value: bool) -> Self {
        self.default = Some(value);
        self
    }

    /// Show the prompt and get user confirmation
    pub fn prompt(self) -> CliResult<bool> {
        let stdout = io::stdout();
        let stdin = io::stdin();
        let mut writer = stdout.lock();
        let mut reader = stdin.lock();
        self.prompt_with(&mut reader, &mut writer)
    }

    /// Render the confirmation prompt to `writer` and parse a line from
    /// `reader`.
    ///
    /// Factored out of [`Confirm::prompt`] so the yes/no parsing and default
    /// branches can be exercised with in-memory readers in tests.
    fn prompt_with<R: BufRead, W: Write>(self, reader: &mut R, writer: &mut W) -> CliResult<bool> {
        // Build prompt suffix
        let suffix = match self.default {
            Some(true) => "[Y/n]",
            Some(false) => "[y/N]",
            None => "[y/n]",
        };

        write!(writer, "{} {}: ", self.message, suffix).map_err(|e| CliError::io(e.to_string()))?;
        writer.flush().map_err(|e| CliError::io(e.to_string()))?;

        // Read input
        let mut input = String::new();
        reader
            .read_line(&mut input)
            .map_err(|e| CliError::io(e.to_string()))?;

        let input = input.trim().to_lowercase();

        // Parse response
        if input.is_empty() {
            if let Some(default) = self.default {
                return Ok(default);
            }
            return Err(CliError::usage("Please enter 'y' or 'n'"));
        }

        match input.as_str() {
            "y" | "yes" | "true" | "1" => Ok(true),
            "n" | "no" | "false" | "0" => Ok(false),
            _ => Err(CliError::usage("Please enter 'y' or 'n'")),
        }
    }
}

/// Password prompt (hidden input)
///
/// # Example
///
/// Pre-existing example - ignored at compile until adapted.
/// ```ignore
/// use octarine::runtime::cli::Password;
///
/// let password = Password::new("Enter password:")
///     .confirm("Confirm password:")
///     .prompt()?;
/// ```
pub struct Password {
    message: String,
    confirmation: Option<String>,
}

impl Password {
    /// Create a new password prompt
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            confirmation: None,
        }
    }

    /// Require confirmation (enter password twice)
    #[must_use]
    pub fn confirm(mut self, message: impl Into<String>) -> Self {
        self.confirmation = Some(message.into());
        self
    }

    /// Show the prompt and get password
    #[cfg(feature = "console")]
    pub fn prompt(self) -> CliResult<String> {
        use std::io::Write;
        let mut term = console::Term::stderr();

        // Print prompt and get first password
        let _ = write!(term, "{}: ", self.message);
        let password = term
            .read_secure_line()
            .map_err(|e| CliError::io(e.to_string()))?;

        // Confirm if required
        if let Some(confirm_msg) = self.confirmation {
            let _ = write!(term, "{}: ", confirm_msg);
            let confirmation = term
                .read_secure_line()
                .map_err(|e| CliError::io(e.to_string()))?;

            if password != confirmation {
                return Err(CliError::usage("Passwords do not match"));
            }
        }

        Ok(password)
    }

    /// Show the prompt and get password (fallback without console - NOT SECURE)
    #[cfg(not(feature = "console"))]
    pub fn prompt(self) -> CliResult<String> {
        // WARNING: This fallback shows the password in the terminal!
        // The console feature should be enabled for secure password input.
        let input = Input::new(format!("{} (WARNING: input visible)", self.message));

        let password = input.prompt()?;

        if let Some(confirm_msg) = self.confirmation {
            let confirmation =
                Input::new(format!("{} (WARNING: input visible)", confirm_msg)).prompt()?;
            if password != confirmation {
                return Err(CliError::usage("Passwords do not match"));
            }
        }

        Ok(password)
    }
}

/// Selection prompt (choose from options)
///
/// # Example
///
/// Pre-existing example - ignored at compile until adapted.
/// ```ignore
/// use octarine::runtime::cli::Select;
///
/// let choice = Select::new("Choose an environment:")
///     .option("development")
///     .option("staging")
///     .option("production")
///     .prompt()?;
/// ```
pub struct Select {
    message: String,
    options: Vec<String>,
    default: Option<usize>,
}

impl Select {
    /// Create a new selection prompt
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            options: Vec::new(),
            default: None,
        }
    }

    /// Add an option
    #[must_use]
    pub fn option(mut self, option: impl Into<String>) -> Self {
        self.options.push(option.into());
        self
    }

    /// Add multiple options
    #[must_use]
    pub fn options(mut self, options: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.options.extend(options.into_iter().map(Into::into));
        self
    }

    /// Set the default option (by index)
    #[must_use]
    pub fn default(mut self, index: usize) -> Self {
        self.default = Some(index);
        self
    }

    /// Show the prompt and get selection
    pub fn prompt(self) -> CliResult<String> {
        let stdout = io::stdout();
        let stdin = io::stdin();
        let mut writer = stdout.lock();
        let mut reader = stdin.lock();
        self.prompt_with(&mut reader, &mut writer)
    }

    /// Render the selection menu to `writer` and resolve a choice from
    /// `reader`.
    ///
    /// Factored out of [`Select::prompt`] so the numeric-parse, name-match,
    /// default, and out-of-range branches can be driven with in-memory
    /// readers in tests.
    fn prompt_with<R: BufRead, W: Write>(
        self,
        reader: &mut R,
        writer: &mut W,
    ) -> CliResult<String> {
        if self.options.is_empty() {
            return Err(CliError::usage("No options provided for selection"));
        }

        // Print message and options
        writeln!(writer, "{}", self.message).map_err(|e| CliError::io(e.to_string()))?;
        for (i, option) in self.options.iter().enumerate() {
            let marker = if Some(i) == self.default { "*" } else { " " };
            writeln!(writer, " {} {}. {}", marker, i.saturating_add(1), option)
                .map_err(|e| CliError::io(e.to_string()))?;
        }

        // Print prompt
        if let Some(default) = self.default {
            write!(writer, "Choice [{}]: ", default.saturating_add(1))
                .map_err(|e| CliError::io(e.to_string()))?;
        } else {
            write!(writer, "Choice: ").map_err(|e| CliError::io(e.to_string()))?;
        }
        writer.flush().map_err(|e| CliError::io(e.to_string()))?;

        // Read input
        let mut input = String::new();
        reader
            .read_line(&mut input)
            .map_err(|e| CliError::io(e.to_string()))?;

        let input = input.trim();

        // Handle empty input with default
        if input.is_empty() {
            if let Some(default) = self.default {
                return self
                    .options
                    .get(default)
                    .cloned()
                    .ok_or_else(|| CliError::usage("Invalid default index"));
            }
            return Err(CliError::usage("Please enter a selection"));
        }

        // Try to parse as number
        if let Ok(num) = input.parse::<usize>() {
            let index = num.saturating_sub(1);
            return self
                .options
                .get(index)
                .cloned()
                .ok_or_else(|| CliError::usage(format!("Invalid choice: {}", num)));
        }

        // Try to match by name
        for option in &self.options {
            if option.eq_ignore_ascii_case(input) {
                return Ok(option.clone());
            }
        }

        Err(CliError::usage(format!("Invalid choice: {}", input)))
    }

    /// Get the index of the selected option
    pub fn prompt_index(self) -> CliResult<usize> {
        if self.options.is_empty() {
            return Err(CliError::usage("No options provided for selection"));
        }

        // Store options before consuming self
        let options = self.options.clone();
        let selected = self.prompt()?;

        // Find the index
        options
            .iter()
            .position(|o| o == &selected)
            .ok_or_else(|| CliError::usage("Selection not found"))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;
    use crate::runtime::cli::ExitCode;

    /// True if `res` is an `Err` carrying a usage (exit code 2) error. `CliError`
    /// is a struct, not an enum, so branches are distinguished by exit code.
    fn is_usage_err<T: std::fmt::Debug>(res: &CliResult<T>) -> bool {
        matches!(res, Err(e) if e.exit_code() == ExitCode::USAGE_ERROR)
    }

    #[test]
    fn test_input_builder() {
        let input = Input::new("Test prompt")
            .default("default_value")
            .allow_empty();

        assert_eq!(input.message, "Test prompt");
        assert_eq!(input.default, Some("default_value".to_string()));
        assert!(input.allow_empty);
    }

    #[test]
    fn test_confirm_builder() {
        let confirm = Confirm::new("Are you sure?").default(false);

        assert_eq!(confirm.message, "Are you sure?");
        assert_eq!(confirm.default, Some(false));
    }

    #[test]
    fn test_password_builder() {
        let password = Password::new("Enter password:").confirm("Confirm password:");

        assert_eq!(password.message, "Enter password:");
        assert_eq!(password.confirmation, Some("Confirm password:".to_string()));
    }

    #[test]
    fn test_select_builder() {
        let select = Select::new("Choose:")
            .option("Option A")
            .option("Option B")
            .options(vec!["Option C", "Option D"])
            .default(1);

        assert_eq!(select.message, "Choose:");
        assert_eq!(select.options.len(), 4);
        assert_eq!(select.default, Some(1));
    }

    #[test]
    fn test_select_empty_options() {
        let select = Select::new("Choose:");
        let result = select.prompt();
        assert!(result.is_err());
    }

    // =========================================================================
    // I/O path tests: drive the real parse/validation branches with in-memory
    // readers/writers via the `prompt_with` seams. These exercise the logic
    // that `prompt()` runs against stdin/stdout, without touching the terminal.
    // =========================================================================

    /// Run `Input::prompt_with` against a canned input line, returning both the
    /// parsed result and what was rendered to the prompt writer.
    fn run_input(input: &Input, line: &str) -> (CliResult<String>, String) {
        // `Input` is not Clone; rebuild an equivalent for each call site.
        let mut reader = io::Cursor::new(line.as_bytes().to_vec());
        let mut out: Vec<u8> = Vec::new();
        let cloned = Input {
            message: input.message.clone(),
            default: input.default.clone(),
            allow_empty: input.allow_empty,
        };
        let res = cloned.prompt_with(&mut reader, &mut out);
        (res, String::from_utf8_lossy(&out).into_owned())
    }

    #[test]
    fn test_input_returns_typed_value() {
        let (res, rendered) = run_input(&Input::new("Name"), "Alice\n");
        assert_eq!(res.expect("value"), "Alice");
        // Prompt is rendered with the trailing ": " separator.
        assert_eq!(rendered, "Name: ");
    }

    #[test]
    fn test_input_trims_whitespace() {
        let (res, _) = run_input(&Input::new("Name"), "  Bob \t\n");
        assert_eq!(res.expect("value"), "Bob");
    }

    #[test]
    fn test_input_empty_uses_default() {
        // Empty line with a default should yield the default, and the prompt
        // must advertise the default in brackets.
        let (res, rendered) = run_input(&Input::new("Name").default("Anonymous"), "\n");
        assert_eq!(res.expect("value"), "Anonymous");
        assert_eq!(rendered, "Name [Anonymous]: ");
    }

    #[test]
    fn test_input_empty_without_default_is_usage_error() {
        // No default and empty-not-allowed: must be a usage error, not a panic
        // or a silent empty string.
        let (res, _) = run_input(&Input::new("Name"), "\n");
        assert!(is_usage_err(&res), "got {res:?}");
    }

    #[test]
    fn test_input_empty_allowed_returns_empty() {
        let (res, _) = run_input(&Input::new("Name").allow_empty(), "\n");
        assert_eq!(res.expect("value"), "");
    }

    #[test]
    fn test_input_eof_without_default_is_usage_error() {
        // EOF (no newline, empty reader) behaves like empty input.
        let (res, _) = run_input(&Input::new("Name"), "");
        assert!(is_usage_err(&res), "got {res:?}");
    }

    fn run_confirm(confirm: Confirm, line: &str) -> (CliResult<bool>, String) {
        let mut reader = io::Cursor::new(line.as_bytes().to_vec());
        let mut out: Vec<u8> = Vec::new();
        let res = confirm.prompt_with(&mut reader, &mut out);
        (res, String::from_utf8_lossy(&out).into_owned())
    }

    #[test]
    fn test_confirm_affirmative_variants() {
        for line in ["y\n", "Y\n", "yes\n", "YES\n", "true\n", "1\n"] {
            let (res, _) = run_confirm(Confirm::new("OK?"), line);
            assert!(res.expect("parsed"), "expected true for {line:?}");
        }
    }

    #[test]
    fn test_confirm_negative_variants() {
        for line in ["n\n", "N\n", "no\n", "false\n", "0\n"] {
            let (res, _) = run_confirm(Confirm::new("OK?"), line);
            assert!(!res.expect("parsed"), "expected false for {line:?}");
        }
    }

    #[test]
    fn test_confirm_empty_uses_default_true() {
        let (res, rendered) = run_confirm(Confirm::new("OK?").default(true), "\n");
        assert!(res.expect("parsed"));
        // Default-true must render as [Y/n].
        assert_eq!(rendered, "OK? [Y/n]: ");
    }

    #[test]
    fn test_confirm_empty_uses_default_false() {
        let (res, rendered) = run_confirm(Confirm::new("OK?").default(false), "\n");
        assert!(!res.expect("parsed"));
        assert_eq!(rendered, "OK? [y/N]: ");
    }

    #[test]
    fn test_confirm_empty_without_default_is_error() {
        let (res, rendered) = run_confirm(Confirm::new("OK?"), "\n");
        assert!(is_usage_err(&res), "got {res:?}");
        assert_eq!(rendered, "OK? [y/n]: ");
    }

    #[test]
    fn test_confirm_invalid_answer_is_error() {
        let (res, _) = run_confirm(Confirm::new("OK?"), "maybe\n");
        assert!(is_usage_err(&res), "got {res:?}");
    }

    fn run_select(select: Select, line: &str) -> (CliResult<String>, String) {
        let mut reader = io::Cursor::new(line.as_bytes().to_vec());
        let mut out: Vec<u8> = Vec::new();
        let res = select.prompt_with(&mut reader, &mut out);
        (res, String::from_utf8_lossy(&out).into_owned())
    }

    fn three_options() -> Select {
        Select::new("Env")
            .option("dev")
            .option("staging")
            .option("prod")
    }

    #[test]
    fn test_select_by_number() {
        // "2" is 1-based; must map to the second option.
        let (res, rendered) = run_select(three_options(), "2\n");
        assert_eq!(res.expect("selection"), "staging");
        // The menu lists all options numbered from 1.
        assert!(rendered.contains(" 1. dev"));
        assert!(rendered.contains(" 2. staging"));
        assert!(rendered.contains(" 3. prod"));
    }

    #[test]
    fn test_select_by_name_case_insensitive() {
        let (res, _) = run_select(three_options(), "PROD\n");
        assert_eq!(res.expect("selection"), "prod");
    }

    #[test]
    fn test_select_number_out_of_range_is_error() {
        // 4 options listed only up to 3; must reject rather than wrap.
        let (res, _) = run_select(three_options(), "4\n");
        assert!(is_usage_err(&res), "got {res:?}");
    }

    #[test]
    fn test_select_zero_maps_to_first_option() {
        // Documents a known quirk: menus are displayed 1-based, but "0" parses
        // as usize 0 and `0.saturating_sub(1)` clamps to index 0, returning the
        // first option rather than an out-of-range error. Asserting the real
        // behavior so a future 1-based-strictness change is a conscious choice,
        // not a silent regression.
        let (res, _) = run_select(three_options(), "0\n");
        assert_eq!(res.expect("selection"), "dev");
    }

    #[test]
    fn test_select_unknown_name_is_error() {
        let (res, _) = run_select(three_options(), "banana\n");
        assert!(is_usage_err(&res), "got {res:?}");
    }

    #[test]
    fn test_select_empty_with_default_returns_default_option() {
        let (res, rendered) = run_select(three_options().default(2), "\n");
        assert_eq!(res.expect("selection"), "prod");
        // The default option is marked with '*' and the prompt shows [3].
        assert!(rendered.contains("* 3. prod"));
        assert!(rendered.contains("Choice [3]: "));
    }

    #[test]
    fn test_select_empty_without_default_is_error() {
        let (res, _) = run_select(three_options(), "\n");
        assert!(is_usage_err(&res), "got {res:?}");
    }
}

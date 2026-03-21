//! Interactive prompts for CLI applications
//!
//! Provides user input, confirmation, selection, and password prompts.

use std::io::{self, BufRead, Write};

use super::{CliError, CliResult};

/// Text input prompt
///
/// # Example
///
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
        let mut handle = stdout.lock();

        // Print prompt
        if let Some(ref default) = self.default {
            write!(handle, "{} [{}]: ", self.message, default)
                .map_err(|e| CliError::io(e.to_string()))?;
        } else {
            write!(handle, "{}: ", self.message).map_err(|e| CliError::io(e.to_string()))?;
        }
        handle.flush().map_err(|e| CliError::io(e.to_string()))?;

        // Read input
        let mut input = String::new();
        stdin
            .lock()
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
        let mut handle = stdout.lock();

        // Build prompt suffix
        let suffix = match self.default {
            Some(true) => "[Y/n]",
            Some(false) => "[y/N]",
            None => "[y/n]",
        };

        write!(handle, "{} {}: ", self.message, suffix).map_err(|e| CliError::io(e.to_string()))?;
        handle.flush().map_err(|e| CliError::io(e.to_string()))?;

        // Read input
        let mut input = String::new();
        stdin
            .lock()
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
        if self.options.is_empty() {
            return Err(CliError::usage("No options provided for selection"));
        }

        let stdout = io::stdout();
        let stdin = io::stdin();
        let mut handle = stdout.lock();

        // Print message and options
        writeln!(handle, "{}", self.message).map_err(|e| CliError::io(e.to_string()))?;
        for (i, option) in self.options.iter().enumerate() {
            let marker = if Some(i) == self.default { "*" } else { " " };
            writeln!(handle, " {} {}. {}", marker, i.saturating_add(1), option)
                .map_err(|e| CliError::io(e.to_string()))?;
        }

        // Print prompt
        if let Some(default) = self.default {
            write!(handle, "Choice [{}]: ", default.saturating_add(1))
                .map_err(|e| CliError::io(e.to_string()))?;
        } else {
            write!(handle, "Choice: ").map_err(|e| CliError::io(e.to_string()))?;
        }
        handle.flush().map_err(|e| CliError::io(e.to_string()))?;

        // Read input
        let mut input = String::new();
        stdin
            .lock()
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
    use super::*;

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
}

//! Progress indicators for CLI applications
//!
//! Provides spinners and progress bars for long-running operations.

use std::time::Duration;

/// Progress bar style presets
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProgressStyle {
    /// Standard progress bar: [████░░░░░░] 40%
    #[default]
    Bar,
    /// Bytes style: [████░░░░░░] 40.5 MB / 100 MB
    Bytes,
    /// Count style: [████░░░░░░] 405/1000
    Count,
    /// Simple percentage: 40%
    Percent,
}

/// A progress bar for tracking completion of tasks
///
/// # Example
///
/// ```ignore
/// use octarine::runtime::cli::ProgressBar;
///
/// let pb = ProgressBar::new(100);
/// pb.set_message("Processing files");
///
/// for i in 0..100 {
///     pb.inc(1);
/// }
///
/// pb.finish_with_message("Done!");
/// ```
pub struct ProgressBar {
    #[cfg(feature = "cli")]
    inner: indicatif::ProgressBar,
    #[cfg(not(feature = "cli"))]
    _total: u64,
}

impl ProgressBar {
    /// Create a new progress bar with a total count
    #[must_use]
    #[allow(clippy::expect_used)]
    pub fn new(total: u64) -> Self {
        #[cfg(feature = "cli")]
        {
            let pb = indicatif::ProgressBar::new(total);
            pb.set_style(
                indicatif::ProgressStyle::default_bar()
                    // SAFETY: Template string is compile-time constant and valid
                    .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} {msg}")
                    .expect("valid template")
                    .progress_chars("█▓░"),
            );
            Self { inner: pb }
        }
        #[cfg(not(feature = "cli"))]
        {
            Self { _total: total }
        }
    }

    /// Create a new progress bar with a specific style
    #[must_use]
    #[allow(clippy::expect_used)]
    pub fn with_style(total: u64, style: ProgressStyle) -> Self {
        #[cfg(feature = "cli")]
        {
            let pb = indicatif::ProgressBar::new(total);
            let template = match style {
                ProgressStyle::Bar => {
                    "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} {msg}"
                }
                ProgressStyle::Bytes => {
                    "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} {msg}"
                }
                ProgressStyle::Count => {
                    "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({percent}%) {msg}"
                }
                ProgressStyle::Percent => "{spinner:.green} {percent}% {msg}",
            };
            pb.set_style(
                indicatif::ProgressStyle::default_bar()
                    // SAFETY: Template strings are compile-time constants and valid
                    .template(template)
                    .expect("valid template")
                    .progress_chars("█▓░"),
            );
            Self { inner: pb }
        }
        #[cfg(not(feature = "cli"))]
        {
            let _ = style;
            Self { _total: total }
        }
    }

    /// Create a hidden progress bar (for quiet mode)
    #[must_use]
    pub fn hidden(total: u64) -> Self {
        #[cfg(feature = "cli")]
        {
            let pb = indicatif::ProgressBar::hidden();
            pb.set_length(total);
            Self { inner: pb }
        }
        #[cfg(not(feature = "cli"))]
        {
            Self { _total: total }
        }
    }

    /// Set the current message
    pub fn set_message(&self, message: impl Into<std::borrow::Cow<'static, str>>) {
        #[cfg(feature = "cli")]
        {
            self.inner.set_message(message);
        }
        #[cfg(not(feature = "cli"))]
        {
            let _ = message;
        }
    }

    /// Increment the progress by a delta
    pub fn inc(&self, delta: u64) {
        #[cfg(feature = "cli")]
        {
            self.inner.inc(delta);
        }
        #[cfg(not(feature = "cli"))]
        {
            let _ = delta;
        }
    }

    /// Set the current position
    pub fn set_position(&self, pos: u64) {
        #[cfg(feature = "cli")]
        {
            self.inner.set_position(pos);
        }
        #[cfg(not(feature = "cli"))]
        {
            let _ = pos;
        }
    }

    /// Set the total length
    pub fn set_length(&self, len: u64) {
        #[cfg(feature = "cli")]
        {
            self.inner.set_length(len);
        }
        #[cfg(not(feature = "cli"))]
        {
            let _ = len;
        }
    }

    /// Get the current position
    #[must_use]
    pub fn position(&self) -> u64 {
        #[cfg(feature = "cli")]
        {
            self.inner.position()
        }
        #[cfg(not(feature = "cli"))]
        {
            0
        }
    }

    /// Get the total length
    #[must_use]
    pub fn length(&self) -> Option<u64> {
        #[cfg(feature = "cli")]
        {
            self.inner.length()
        }
        #[cfg(not(feature = "cli"))]
        {
            Some(self._total)
        }
    }

    /// Finish the progress bar
    pub fn finish(&self) {
        #[cfg(feature = "cli")]
        {
            self.inner.finish();
        }
    }

    /// Finish with a message
    pub fn finish_with_message(&self, message: impl Into<std::borrow::Cow<'static, str>>) {
        #[cfg(feature = "cli")]
        {
            self.inner.finish_with_message(message);
        }
        #[cfg(not(feature = "cli"))]
        {
            let _ = message;
        }
    }

    /// Finish and clear from screen
    pub fn finish_and_clear(&self) {
        #[cfg(feature = "cli")]
        {
            self.inner.finish_and_clear();
        }
    }

    /// Abandon the progress bar (leave it on screen without completion)
    pub fn abandon(&self) {
        #[cfg(feature = "cli")]
        {
            self.inner.abandon();
        }
    }

    /// Abandon with a message
    pub fn abandon_with_message(&self, message: impl Into<std::borrow::Cow<'static, str>>) {
        #[cfg(feature = "cli")]
        {
            self.inner.abandon_with_message(message);
        }
        #[cfg(not(feature = "cli"))]
        {
            let _ = message;
        }
    }

    /// Enable steady tick for the spinner
    pub fn enable_steady_tick(&self, interval: Duration) {
        #[cfg(feature = "cli")]
        {
            self.inner.enable_steady_tick(interval);
        }
        #[cfg(not(feature = "cli"))]
        {
            let _ = interval;
        }
    }
}

/// A spinner for indeterminate operations
///
/// # Example
///
/// ```ignore
/// use octarine::runtime::cli::Spinner;
///
/// let spinner = Spinner::new("Loading...");
///
/// // Do work...
///
/// spinner.finish_with_message("✓ Done!");
/// ```
pub struct Spinner {
    #[cfg(feature = "cli")]
    inner: indicatif::ProgressBar,
    #[cfg(not(feature = "cli"))]
    _phantom: std::marker::PhantomData<()>,
}

impl Spinner {
    /// Create a new spinner with a message
    #[must_use]
    #[allow(clippy::expect_used)]
    pub fn new(message: impl Into<std::borrow::Cow<'static, str>>) -> Self {
        #[cfg(feature = "cli")]
        {
            let pb = indicatif::ProgressBar::new_spinner();
            pb.set_style(
                indicatif::ProgressStyle::default_spinner()
                    // SAFETY: Template string is compile-time constant and valid
                    .template("{spinner:.green} {msg}")
                    .expect("valid template"),
            );
            pb.set_message(message);
            pb.enable_steady_tick(Duration::from_millis(100));
            Self { inner: pb }
        }
        #[cfg(not(feature = "cli"))]
        {
            let _ = message;
            Self {
                _phantom: std::marker::PhantomData,
            }
        }
    }

    /// Create a hidden spinner (for quiet mode)
    #[must_use]
    pub fn hidden() -> Self {
        #[cfg(feature = "cli")]
        {
            Self {
                inner: indicatif::ProgressBar::hidden(),
            }
        }
        #[cfg(not(feature = "cli"))]
        {
            Self {
                _phantom: std::marker::PhantomData,
            }
        }
    }

    /// Set the spinner message
    pub fn set_message(&self, message: impl Into<std::borrow::Cow<'static, str>>) {
        #[cfg(feature = "cli")]
        {
            self.inner.set_message(message);
        }
        #[cfg(not(feature = "cli"))]
        {
            let _ = message;
        }
    }

    /// Finish the spinner
    pub fn finish(&self) {
        #[cfg(feature = "cli")]
        {
            self.inner.finish();
        }
    }

    /// Finish with a message
    pub fn finish_with_message(&self, message: impl Into<std::borrow::Cow<'static, str>>) {
        #[cfg(feature = "cli")]
        {
            self.inner.finish_with_message(message);
        }
        #[cfg(not(feature = "cli"))]
        {
            let _ = message;
        }
    }

    /// Finish and clear from screen
    pub fn finish_and_clear(&self) {
        #[cfg(feature = "cli")]
        {
            self.inner.finish_and_clear();
        }
    }

    /// Suspend the spinner to print something
    #[cfg(feature = "cli")]
    pub fn suspend<F, R>(&self, f: F) -> R
    where
        F: FnOnce() -> R,
    {
        self.inner.suspend(f)
    }

    /// Suspend the spinner to print something (no-op without cli feature)
    #[cfg(not(feature = "cli"))]
    pub fn suspend<F, R>(&self, f: F) -> R
    where
        F: FnOnce() -> R,
    {
        f()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_progress_bar_creation() {
        let pb = ProgressBar::new(100);
        assert_eq!(pb.length(), Some(100));
    }

    #[test]
    fn test_progress_bar_hidden() {
        let pb = ProgressBar::hidden(50);
        // Hidden progress bar should still work
        pb.set_message("test");
        pb.inc(10);
        pb.finish();
    }

    #[test]
    fn test_progress_styles() {
        let _ = ProgressBar::with_style(100, ProgressStyle::Bar);
        let _ = ProgressBar::with_style(100, ProgressStyle::Bytes);
        let _ = ProgressBar::with_style(100, ProgressStyle::Count);
        let _ = ProgressBar::with_style(100, ProgressStyle::Percent);
    }

    #[test]
    fn test_spinner_creation() {
        let spinner = Spinner::new("Loading...");
        spinner.set_message("Still loading...");
        spinner.finish_with_message("Done!");
    }

    #[test]
    fn test_spinner_hidden() {
        let spinner = Spinner::hidden();
        spinner.set_message("test");
        spinner.finish();
    }

    #[test]
    fn test_spinner_suspend() {
        let spinner = Spinner::new("Working...");
        let result = spinner.suspend(|| 42);
        assert_eq!(result, 42);
        spinner.finish();
    }
}

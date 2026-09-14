// CLI Utilities — shared terminal output formatters and helpers.

use std::fmt::{self, Display};
use std::time::Duration;

// ── Color helpers ───────────────────────────────────────────────────────

/// ANSI color codes for terminal output.
/// Respects NO_COLOR environment variable.
pub struct Color;

impl Color {
    fn enabled() -> bool {
        std::env::var("NO_COLOR").is_err()
            && std::env::var("CHAKRAVYUH_NO_COLOR").is_err()
    }

    pub fn green(s: &str) -> String {
        if Self::enabled() { format!("\x1b[32m{}\x1b[0m", s) } else { s.to_string() }
    }

    pub fn red(s: &str) -> String {
        if Self::enabled() { format!("\x1b[31m{}\x1b[0m", s) } else { s.to_string() }
    }

    pub fn yellow(s: &str) -> String {
        if Self::enabled() { format!("\x1b[33m{}\x1b[0m", s) } else { s.to_string() }
    }

    pub fn blue(s: &str) -> String {
        if Self::enabled() { format!("\x1b[34m{}\x1b[0m", s) } else { s.to_string() }
    }

    pub fn cyan(s: &str) -> String {
        if Self::enabled() { format!("\x1b[36m{}\x1b[0m", s) } else { s.to_string() }
    }

    pub fn dim(s: &str) -> String {
        if Self::enabled() { format!("\x1b[2m{}\x1b[0m", s) } else { s.to_string() }
    }

    pub fn bold(s: &str) -> String {
        if Self::enabled() { format!("\x1b[1m{}\x1b[0m", s) } else { s.to_string() }
    }
}

// ── Status indicators ───────────────────────────────────────────────────

/// A styled status indicator for CLI output.
pub struct StatusIndicator;

impl StatusIndicator {
    pub fn ok(msg: &str) -> String {
        format!("{} {}", Color::green("OK"), msg)
    }

    pub fn fail(msg: &str) -> String {
        format!("{} {}", Color::red("FAIL"), msg)
    }

    pub fn warn(msg: &str) -> String {
        format!("{} {}", Color::yellow("WARN"), msg)
    }

    pub fn info(msg: &str) -> String {
        format!("{} {}", Color::blue("INFO"), msg)
    }

    pub fn pass() -> String {
        Color::green("PASS").to_string()
    }

    pub fn denied() -> String {
        Color::red("DENIED").to_string()
    }

    pub fn challenged() -> String {
        Color::yellow("CHALLENGED").to_string()
    }

    pub fn escalated() -> String {
        Color::cyan("ESCALATED").to_string()
    }
}

// ── Formatters ──────────────────────────────────────────────────────────

/// Format a file size in human-readable form.
pub fn format_size(bytes: usize) -> String {
    const KB: usize = 1024;
    const MB: usize = 1024 * KB;
    const GB: usize = 1024 * MB;
    match bytes {
        0..=KB => format!("{} B", bytes),
        b if b < MB => format!("{:.1} KB", b as f64 / KB as f64),
        b if b < GB => format!("{:.1} MB", b as f64 / MB as f64),
        b => format!("{:.2} GB", b as f64 / GB as f64),
    }
}

/// Format a duration in human-readable form.
pub fn format_duration(dur: Duration) -> String {
    let nanos = dur.as_nanos();
    if nanos < 1_000 {
        format!("{} ns", nanos)
    } else if nanos < 1_000_000 {
        format!("{:.1} us", nanos as f64 / 1_000.0)
    } else if nanos < 1_000_000_000 {
        format!("{:.1} ms", nanos as f64 / 1_000_000.0)
    } else {
        format!("{:.2} s", dur.as_secs_f64())
    }
}

/// Format a risk score as a colored bar.
pub fn format_risk_bar(score: f64, width: usize) -> String {
    let filled = ((score * width as f64).round() as usize).min(width);
    let empty = width - filled;
    let bar: String = "#".repeat(filled) + &".".repeat(empty);
    let color = if score >= 0.8 {
        Color::red(&bar)
    } else if score >= 0.5 {
        Color::yellow(&bar)
    } else {
        Color::green(&bar)
    };
    format!("[{}] {:.3}", color, score)
}

/// Format a table row with aligned columns.
pub fn table_row(columns: &[&str], widths: &[usize]) -> String {
    let parts: Vec<String> = columns
        .iter()
        .zip(widths.iter())
        .map(|(col, w)| format!("{:<w$}", col, w = w))
        .collect();
    parts.join(" | ")
}

/// Print a table header with separator.
pub fn print_table(headers: &[&str], rows: &[Vec<String>]) {
    if headers.is_empty() {
        return;
    }
    let col_count = headers.len();
    // Compute column widths.
    let mut widths: Vec<usize> = headers.iter().map(|h| h.len()).collect();
    for row in rows {
        for (i, cell) in row.iter().enumerate() {
            if i < col_count && cell.len() > widths[i] {
                widths[i] = cell.len();
            }
        }
    }
    // Print header.
    let header_strs: Vec<&str> = headers.iter().map(|s| s.as_ref()).collect();
    println!("{}", table_row(&header_strs, &widths));
    // Print separator.
    let sep: Vec<String> = widths.iter().map(|w| "-".repeat(*w)).collect();
    let sep_strs: Vec<&str> = sep.iter().map(|s| s.as_str()).collect();
    println!("{}", table_row(&sep_strs, &widths));
    // Print rows.
    for row in rows {
        let row_strs: Vec<&str> = row.iter().map(|s| s.as_str()).collect();
        println!("{}", table_row(&row_strs, &widths));
    }
}

// ── Exit codes ──────────────────────────────────────────────────────────

/// CLI exit codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitCode {
    /// Successful execution.
    Ok = 0,
    /// General failure.
    GeneralError = 1,
    /// Configuration error.
    ConfigError = 2,
    /// Policy compilation error.
    PolicyError = 3,
    /// Evaluation denied (for batch mode).
    Denied = 4,
    /// Connection error (remote endpoint).
    ConnectionError = 5,
    /// Partial success (some items failed).
    PartialFailure = 6,
}

impl ExitCode {
    pub fn code(&self) -> i32 {
        *self as i32
    }
}

impl Display for ExitCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExitCode::Ok => write!(f, "OK"),
            ExitCode::GeneralError => write!(f, "General Error"),
            ExitCode::ConfigError => write!(f, "Configuration Error"),
            ExitCode::PolicyError => write!(f, "Policy Error"),
            ExitCode::Denied => write!(f, "Denied"),
            ExitCode::ConnectionError => write!(f, "Connection Error"),
            ExitCode::PartialFailure => write!(f, "Partial Failure"),
        }
    }
}

// ── Version banner ──────────────────────────────────────────────────────

/// Print the CHAKRAVYUH version banner.
pub fn print_banner() {
    let version = env!("CARGO_PKG_VERSION");
    println!(
        "{} v{} — {}",
        Color::bold("CHAKRAVYUH"),
        Color::cyan(version),
        "Open-source security operating system for autonomous AI"
    );
    println!(
        "  {} | {} | {}",
        Color::dim(&format!("License: Apache-2.0")),
        Color::dim(&format!("Repo: https://github.com/vinomoid/chakravyuh")),
        Color::dim(&format!("Docs: https://docs.chakravyuh.org")),
    );
    println!();
}

// ── Section header ──────────────────────────────────────────────────────

/// Print a styled section header.
pub fn section(title: &str) {
    println!("\n{} {}", Color::bold("===>"), Color::bold(title));
}

/// Print a sub-section header.
pub fn sub_section(title: &str) {
    println!("\n{} {}", Color::bold("---"), Color::bold(title));
}

/// Print a key-value pair.
pub fn kv(key: &str, value: &str) {
    println!("  {:<28} {}", Color::dim(key), value);
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_size() {
        assert_eq!(format_size(0), "0 B");
        assert_eq!(format_size(512), "512 B");
        assert_eq!(format_size(2048), "2.0 KB");
        assert_eq!(format_size(3 * 1024 * 1024), "3.0 MB");
    }

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(Duration::from_nanos(500)), "500 ns");
        assert_eq!(format_duration(Duration::from_micros(1500)), "1.5 ms");
        assert_eq!(format_duration(Duration::from_millis(1500)), "1.50 s");
    }

    #[test]
    fn test_exit_code() {
        assert_eq!(ExitCode::Ok.code(), 0);
        assert_eq!(ExitCode::GeneralError.code(), 1);
        assert_eq!(ExitCode::Denied.code(), 4);
    }

    #[test]
    fn test_color_respects_no_color() {
        std::env::set_var("NO_COLOR", "1");
        assert_eq!(Color::green("x"), "x");
        assert_eq!(Color::red("x"), "x");
        std::env::remove_var("NO_COLOR");
    }

    #[test]
    fn test_table_output() {
        // Just verify it doesn't panic.
        print_table(
            &["Name", "Status"],
            &[
                vec!["Shield".to_string(), "OK".to_string()],
                vec!["Threat".to_string(), "OK".to_string()],
            ],
        );
    }

    #[test]
    fn test_risk_bar() {
        let bar = format_risk_bar(0.3, 20);
        assert!(bar.contains("0.300"));
    }
}

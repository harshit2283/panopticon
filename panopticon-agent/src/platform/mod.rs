//! Platform-specific functionality: TLS library discovery and /proc scanning.
//!
//! ELF parsing functions are cross-platform (testable on macOS).
//! `/proc`-based scanning is Linux-only.

pub mod go_read;
// Used only by the Linux scanner; its parser is tested everywhere.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub mod overlay;
pub mod proc_scanner;

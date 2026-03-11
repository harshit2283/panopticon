//! Platform-specific functionality: TLS library discovery and /proc scanning.
//!
//! ELF parsing functions are cross-platform (testable on macOS).
//! `/proc`-based scanning is Linux-only.

pub mod proc_scanner;

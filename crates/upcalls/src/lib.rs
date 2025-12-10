//! Upcall wrapper binaries for devaipod sandboxed agents.
//!
//! This crate provides restricted wrapper binaries that can be placed in
//! `/usr/lib/devaipod/upcalls/` to allow sandboxed agents to perform
//! specific operations safely.
//!
//! ## Available binaries
//!
//! - `gh-restricted`: Configurable GitHub CLI wrapper with optional read-only
//!   or restricted write mode. Configure via `~/.config/gh-restricted.toml`:
//!   ```toml
//!   # Read-only mode (no writes allowed)
//!   allow-read-all = true
//!   ```

pub mod config;
pub mod gh_restricted;

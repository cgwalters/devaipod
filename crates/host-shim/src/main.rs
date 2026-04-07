//! Thin host-side shim for devaipod.
//!
//! When installed on the host as `devaipod`, this binary detects that it is
//! *not* running inside the devaipod container (no `DEVAIPOD_CONTAINER=1`)
//! and transparently proxies the command into the running container via
//! `podman exec`.
//!
//! The key feature is **cwd translation**: if the user's working directory
//! falls under a configured `[sources]` path, the shim maps it to the
//! corresponding `/mnt/<name>/...` path inside the container. This lets
//! users run `devaipod diff` from their source repo and have it Just Work.
//!
//! ```text
//! # On the host:
//! cd ~/src/github/org/repo
//! devaipod diff                    # the shim translates this to:
//! # podman exec -w /mnt/src/github/org/repo -ti devaipod devaipod diff
//! ```

use std::collections::HashMap;
use std::env;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

// --- Minimal config parsing (just enough for [sources]) ---

/// Minimal config: we only care about `[sources]`.
#[derive(serde::Deserialize, Default)]
#[serde(default)]
struct Config {
    /// Named source directories.
    sources: HashMap<String, SourceEntry>,
}

/// Source entry: shorthand string or full struct.
#[derive(serde::Deserialize, Clone)]
#[serde(untagged)]
enum SourceEntry {
    /// `src = "~/src"`
    Short(String),
    /// `src = { path = "~/src", access = "readonly" }`
    Full(SourceEntryFull),
}

/// Full source entry.
#[derive(serde::Deserialize, Clone)]
struct SourceEntryFull {
    path: String,
    #[allow(dead_code)]
    #[serde(default)]
    access: Option<String>,
}

impl SourceEntry {
    fn path(&self) -> &str {
        match self {
            Self::Short(p) => p,
            Self::Full(f) => &f.path,
        }
    }
}

/// Expand `~/...` to `$HOME/...`.
fn expand_tilde(path: &str) -> PathBuf {
    if let Some(suffix) = path.strip_prefix("~/") {
        if let Ok(home) = env::var("HOME") {
            return PathBuf::from(home).join(suffix);
        }
    }
    PathBuf::from(path)
}

/// Load config from the standard location.
fn load_config() -> Config {
    let path = dirs_config().join("devaipod.toml");
    match std::fs::read_to_string(&path) {
        Ok(contents) => toml::from_str(&contents).unwrap_or_default(),
        Err(_) => Config::default(),
    }
}

/// XDG config dir or ~/.config.
fn dirs_config() -> PathBuf {
    env::var("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let home = env::var("HOME").unwrap_or_else(|_| "/root".to_string());
            PathBuf::from(home).join(".config")
        })
}

// --- CWD translation ---

/// A resolved source mount: host path → container mount point.
struct SourceMount {
    /// Canonical host path (e.g. `/home/user/src`)
    host_path: PathBuf,
    /// Container mount point (e.g. `/mnt/src`)
    container_path: String,
}

/// Build the list of source mounts from config.
fn resolve_sources(config: &Config) -> Vec<SourceMount> {
    config
        .sources
        .iter()
        .filter_map(|(name, entry)| {
            let expanded = expand_tilde(entry.path());
            // Canonicalize to resolve symlinks; skip sources that don't exist
            let canonical = std::fs::canonicalize(&expanded).ok()?;
            Some(SourceMount {
                host_path: canonical,
                container_path: format!("/mnt/{name}"),
            })
        })
        .collect()
}

/// Translate a host cwd to a container-side path using source mounts.
///
/// Returns `Some("/mnt/src/github/org/repo")` if cwd is under a source,
/// or `None` if no source matches.
fn translate_cwd(cwd: &Path, sources: &[SourceMount]) -> Option<String> {
    translate_cwd_inner(cwd, sources, true)
}

/// Inner implementation that optionally canonicalizes paths.
/// Canonicalization resolves symlinks for reliable matching but
/// requires paths to exist on disk.
fn translate_cwd_inner(cwd: &Path, sources: &[SourceMount], canonicalize: bool) -> Option<String> {
    let cwd = if canonicalize {
        std::fs::canonicalize(cwd).unwrap_or_else(|_| cwd.to_path_buf())
    } else {
        cwd.to_path_buf()
    };

    // Try each source mount, longest host_path first (most specific match)
    let mut sorted: Vec<&SourceMount> = sources.iter().collect();
    sorted.sort_by(|a, b| b.host_path.as_os_str().len().cmp(&a.host_path.as_os_str().len()));

    for source in sorted {
        if let Ok(suffix) = cwd.strip_prefix(&source.host_path) {
            let suffix_str = suffix.to_string_lossy();
            if suffix_str.is_empty() {
                return Some(source.container_path.clone());
            }
            return Some(format!("{}/{}", source.container_path, suffix_str));
        }
    }
    None
}

// --- Main ---

fn main() {
    // If we're already inside the container, exec the real binary directly.
    // This shouldn't happen (the container has the real binary at the same
    // path), but handle it gracefully.
    if env::var("DEVAIPOD_CONTAINER").as_deref() == Ok("1") {
        eprintln!("devaipod-host: already inside container, this shim should not be here");
        std::process::exit(1);
    }

    let args: Vec<String> = env::args().skip(1).collect();
    let container_name =
        env::var("DEVAIPOD_NAME").unwrap_or_else(|_| "devaipod".to_string());

    let config = load_config();
    let sources = resolve_sources(&config);

    let cwd = env::current_dir().ok();
    let container_cwd = cwd.as_deref().and_then(|c| translate_cwd(c, &sources));

    let is_tty = std::io::IsTerminal::is_terminal(&std::io::stdin());

    // Build: podman exec [-ti] [-w <dir>] <container> devaipod <args...>
    let mut cmd = Command::new("podman");
    cmd.arg("exec");
    if is_tty {
        cmd.arg("-ti");
    } else {
        cmd.arg("-i");
    }

    if let Some(ref cwd) = container_cwd {
        cmd.args(["-w", cwd]);
    }

    cmd.arg(&container_name);
    cmd.arg("devaipod");
    cmd.args(&args);

    // exec replaces this process
    let err = cmd.exec();
    eprintln!("devaipod: failed to exec podman: {err}");
    std::process::exit(1);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_translate_cwd_match() {
        let sources = vec![SourceMount {
            host_path: PathBuf::from("/home/user/src"),
            container_path: "/mnt/src".to_string(),
        }];
        assert_eq!(
            translate_cwd_inner(Path::new("/home/user/src"), &sources, false),
            Some("/mnt/src".to_string())
        );
    }

    #[test]
    fn test_translate_cwd_subpath() {
        let sources = vec![SourceMount {
            host_path: PathBuf::from("/home/user/src"),
            container_path: "/mnt/src".to_string(),
        }];
        assert_eq!(
            translate_cwd_inner(Path::new("/home/user/src/github/org/repo"), &sources, false),
            Some("/mnt/src/github/org/repo".to_string())
        );
    }

    #[test]
    fn test_translate_cwd_no_match() {
        let sources = vec![SourceMount {
            host_path: PathBuf::from("/home/user/src"),
            container_path: "/mnt/src".to_string(),
        }];
        assert_eq!(
            translate_cwd_inner(Path::new("/tmp/foo"), &sources, false),
            None
        );
    }

    #[test]
    fn test_translate_cwd_longest_prefix_wins() {
        let sources = vec![
            SourceMount {
                host_path: PathBuf::from("/home/user/src"),
                container_path: "/mnt/src".to_string(),
            },
            SourceMount {
                host_path: PathBuf::from("/home/user/src/work"),
                container_path: "/mnt/work".to_string(),
            },
        ];
        assert_eq!(
            translate_cwd_inner(Path::new("/home/user/src/work/project"), &sources, false),
            Some("/mnt/work/project".to_string())
        );
        assert_eq!(
            translate_cwd_inner(Path::new("/home/user/src/other"), &sources, false),
            Some("/mnt/src/other".to_string())
        );
    }

    #[test]
    fn test_expand_tilde() {
        // With HOME set (always true in test), ~/foo expands
        let result = expand_tilde("~/foo/bar");
        assert!(result.to_string_lossy().ends_with("/foo/bar"));
        assert!(!result.to_string_lossy().starts_with("~"));

        // Absolute paths pass through
        assert_eq!(expand_tilde("/opt/src"), PathBuf::from("/opt/src"));

        // Relative paths pass through
        assert_eq!(expand_tilde("relative/path"), PathBuf::from("relative/path"));
    }
}

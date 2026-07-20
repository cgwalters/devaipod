//! Thin host-side shim for devaipod.
//!
//! When installed on the host as `devaipod`, this binary detects that it is
//! *not* running inside the devaipod container (no `DEVAIPOD_CONTAINER=1`)
//! and transparently proxies the command into the running container via
//! `podman exec`.
//!
//! The shim also handles lifecycle commands (`start`, `stop`, `status`) that
//! manage the devaipod container itself, replacing the Justfile's
//! `container-run` recipe.
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
use std::time::{Duration, Instant};

// --- Minimal config parsing (just enough for [sources]) ---

/// Minimal config: we only care about `[sources]` and `image`.
#[derive(serde::Deserialize, Default)]
#[serde(default)]
struct Config {
    /// Named source directories.
    sources: HashMap<String, SourceEntry>,
    /// Default container image for `devaipod server start`.
    image: Option<String>,
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
    if let Some(suffix) = path.strip_prefix("~/")
        && let Ok(home) = env::var("HOME")
    {
        return PathBuf::from(home).join(suffix);
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
    sorted.sort_by(|a, b| {
        b.host_path
            .as_os_str()
            .len()
            .cmp(&a.host_path.as_os_str().len())
    });

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

// --- Lifecycle commands (start / stop / status) ---

/// Default port for the web UI.
const DEFAULT_PORT: &str = "8080";
/// Default container image (the published production image).
const DEFAULT_IMAGE: &str = "ghcr.io/cgwalters/devaipod:latest";
/// Environment variable to override the container image.
const IMAGE_ENV: &str = "DEVAIPOD_IMAGE";
/// How long to wait for the server container to appear.
const START_TIMEOUT: Duration = Duration::from_secs(30);

/// Find the podman socket path. Returns the path or exits with an error.
fn find_podman_socket() -> PathBuf {
    // Linux: $XDG_RUNTIME_DIR/podman/podman.sock
    if let Ok(xdg) = env::var("XDG_RUNTIME_DIR") {
        let sock = PathBuf::from(&xdg).join("podman/podman.sock");
        if sock.exists() {
            return sock;
        }
    }
    // macOS: ask podman machine
    if let Ok(output) = Command::new("podman")
        .args([
            "machine",
            "inspect",
            "--format",
            "{{.ConnectionInfo.PodmanSocket.Path}}",
        ])
        .output()
        && output.status.success()
    {
        let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !path.is_empty() {
            let sock = PathBuf::from(&path);
            if sock.exists() {
                return sock;
            }
        }
    }
    eprintln!("devaipod: could not find podman socket");
    eprintln!("  Linux: set XDG_RUNTIME_DIR and ensure podman socket is active");
    eprintln!("  macOS: run 'podman machine start'");
    std::process::exit(1);
}

/// Determine the socket path to pass as HOST_SOCKET (what the container
/// uses as a bind-mount source for sibling containers).
///
/// When `has_xdg_runtime` is true (Linux), this is the real socket path.
/// Otherwise (macOS) the container runs in the podman VM, so we use the
/// VM's well-known path.
fn host_socket_for_container(actual_socket: &Path, has_xdg_runtime: bool) -> PathBuf {
    if has_xdg_runtime {
        actual_socket.to_path_buf()
    } else {
        PathBuf::from("/run/podman/podman.sock")
    }
}

/// Parse `--flag VALUE` pairs from a slice, returning (port, image).
/// Unrecognised flags cause an error exit.
fn parse_start_flags(args: &[String]) -> (String, Option<String>) {
    let mut port = DEFAULT_PORT.to_string();
    let mut image: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--port" => {
                i += 1;
                port = args.get(i).cloned().unwrap_or_else(|| {
                    eprintln!("devaipod server start: --port requires a value");
                    std::process::exit(1);
                });
            }
            "--image" => {
                i += 1;
                image = Some(args.get(i).cloned().unwrap_or_else(|| {
                    eprintln!("devaipod server start: --image requires a value");
                    std::process::exit(1);
                }));
            }
            other => {
                eprintln!("devaipod server start: unknown flag '{other}'");
                std::process::exit(1);
            }
        }
        i += 1;
    }
    (port, image)
}

/// Resolve the container image to use.
///
/// Precedence: `--image` flag > `DEVAIPOD_IMAGE` env > config `image` > compiled default.
fn resolve_image(flag: Option<String>, config: &Config) -> String {
    if let Some(img) = flag {
        return img;
    }
    if let Ok(img) = env::var(IMAGE_ENV) {
        if !img.is_empty() {
            return img;
        }
    }
    if let Some(ref img) = config.image {
        return img.clone();
    }
    DEFAULT_IMAGE.to_string()
}

/// `devaipod server start [--port PORT] [--image IMAGE]`
fn cmd_start(args: &[String], container_name: &str, config: &Config) {
    let (port, image_flag) = parse_start_flags(args);
    let image = resolve_image(image_flag, config);
    let home = env::var("HOME").unwrap_or_else(|_| {
        eprintln!("devaipod server start: HOME is not set");
        std::process::exit(1);
    });

    // 1. Find podman socket
    let socket = find_podman_socket();
    eprintln!("Using podman socket: {}", socket.display());

    // 2. Create directories
    let ssh_dir = PathBuf::from(&home).join(format!(".ssh/config.d/{container_name}"));
    let workspaces_dir =
        PathBuf::from(&home).join(format!(".local/share/{container_name}/workspaces"));
    for dir in [&ssh_dir, &workspaces_dir] {
        if let Err(e) = std::fs::create_dir_all(dir) {
            eprintln!(
                "devaipod server start: failed to create {}: {e}",
                dir.display()
            );
            std::process::exit(1);
        }
    }

    // 3. Create state volume if needed
    let state_vol = format!("{container_name}-state");
    let vol_exists = Command::new("podman")
        .args(["volume", "exists", &state_vol])
        .status()
        .is_ok_and(|s| s.success());
    if !vol_exists {
        let status = Command::new("podman")
            .args(["volume", "create", &state_vol])
            .status();
        match status {
            Ok(s) if s.success() => eprintln!("Created volume {state_vol}"),
            _ => {
                eprintln!("devaipod server start: failed to create volume {state_vol}");
                std::process::exit(1);
            }
        }
    }

    // 4. Determine HOST_SOCKET
    let is_linux = env::var("XDG_RUNTIME_DIR").is_ok();
    let host_socket = host_socket_for_container(&socket, is_linux);

    // 5. Config file path
    let config_path = PathBuf::from(&home).join(".config/devaipod.toml");
    if !config_path.exists() {
        eprintln!(
            "Warning: {} not found; container may exit. Run 'devaipod init' on the host first.",
            config_path.display()
        );
    }

    // 6. Run the launcher container
    let launcher_name = format!("{container_name}-launcher");
    let mut cmd = Command::new("podman");
    cmd.args([
        "run",
        "-d",
        "--name",
        &launcher_name,
        "--privileged",
        "--replace",
    ]);

    if is_linux {
        cmd.args(["--add-host", "host.containers.internal:host-gateway"]);
    }

    cmd.args(["-v", &format!("{}:/run/docker.sock", host_socket.display())]);
    cmd.args([
        "-e",
        &format!("DEVAIPOD_HOST_SOCKET={}", host_socket.display()),
    ]);
    cmd.args(["-e", &format!("DEVAIPOD_HOST_PORT={port}")]);
    cmd.args(["-e", &format!("DEVAIPOD_HOST_HOME={home}")]);
    cmd.args(["-e", &format!("DEVAIPOD_CONTAINER_NAME={launcher_name}")]);
    cmd.args([
        "-v",
        &format!("{}:/var/lib/devaipod-workspaces", workspaces_dir.display()),
    ]);
    cmd.args([
        "-e",
        &format!("DEVAIPOD_HOST_WORKDIR={}", workspaces_dir.display()),
    ]);
    cmd.args(["-v", &format!("{state_vol}:/var/lib/devaipod")]);
    cmd.args([
        "-v",
        &format!("{}:/root/.config/devaipod.toml:ro", config_path.display()),
    ]);
    cmd.args(["-v", &format!("{}:/run/devaipod-ssh:Z", ssh_dir.display())]);
    cmd.arg(&image);

    let status = cmd.status();
    match status {
        Ok(s) if s.success() => {}
        Ok(s) => {
            eprintln!(
                "devaipod server start: podman run failed (exit {})",
                s.code().unwrap_or(-1)
            );
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("devaipod server start: failed to exec podman: {e}");
            std::process::exit(1);
        }
    }

    // 7. Wait for the server container to appear
    eprintln!("Launcher started; waiting for server container '{container_name}'...");
    let deadline = Instant::now() + START_TIMEOUT;
    let mut found = false;
    while Instant::now() < deadline {
        if Command::new("podman")
            .args(["inspect", container_name])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
        {
            found = true;
            break;
        }
        std::thread::sleep(Duration::from_secs(1));
    }

    if !found {
        eprintln!(
            "ERROR: Server container '{container_name}' did not start within {}s.",
            START_TIMEOUT.as_secs()
        );
        eprintln!("Check: podman logs {launcher_name}");
        std::process::exit(1);
    }

    eprintln!("devaipod started (port {port})");
    eprintln!("Web UI: http://127.0.0.1:{port}/");
}

/// `devaipod stop`
fn cmd_stop(container_name: &str) {
    let launcher_name = format!("{container_name}-launcher");

    // Stop & remove both containers, ignoring errors (they may not exist).
    for name in [container_name, launcher_name.as_str()] {
        let _ = Command::new("podman")
            .args(["stop", name])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        let _ = Command::new("podman")
            .args(["rm", name])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }

    eprintln!("devaipod stopped");
}

/// `devaipod status`
fn cmd_status(container_name: &str) {
    let output = Command::new("podman")
        .args([
            "inspect",
            container_name,
            "--format",
            "{{.State.Status}}|{{.State.StartedAt}}|{{.State.Running}}",
        ])
        .output();

    match output {
        Ok(o) if o.status.success() => {
            let raw = String::from_utf8_lossy(&o.stdout);
            let raw = raw.trim();
            let parts: Vec<&str> = raw.splitn(3, '|').collect();
            let state = parts.first().unwrap_or(&"unknown");
            let started = parts.get(1).unwrap_or(&"");
            let running = parts.get(2).unwrap_or(&"false");

            eprintln!("Container: {container_name}");
            eprintln!("State:     {state} (running={running})");

            if *running == "true" {
                // Show port mapping
                if let Ok(port_out) = Command::new("podman")
                    .args(["port", container_name])
                    .output()
                    && port_out.status.success()
                {
                    let ports = String::from_utf8_lossy(&port_out.stdout);
                    let ports = ports.trim();
                    if !ports.is_empty() {
                        eprintln!("Ports:     {ports}");
                    }
                }
                // Show uptime (just the started-at timestamp)
                if !started.is_empty() {
                    eprintln!("Started:   {started}");
                }
            }
        }
        _ => {
            eprintln!("Container '{container_name}' not found");
            std::process::exit(1);
        }
    }
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
    let container_name = env::var("DEVAIPOD_NAME").unwrap_or_else(|_| "devaipod".to_string());

    let config = load_config();

    // Intercept `server` subcommand — these manage the container itself and
    // must NOT be proxied via `podman exec`.
    if args.first().map(|s| s.as_str()) == Some("server") {
        let subcmd = args.get(1).map(|s| s.as_str());
        match subcmd {
            Some("start") => {
                cmd_start(&args[2..], &container_name, &config);
                return;
            }
            Some("stop") => {
                cmd_stop(&container_name);
                return;
            }
            Some("status") => {
                cmd_status(&container_name);
                return;
            }
            Some(other) => {
                eprintln!("devaipod server: unknown subcommand '{other}'");
                eprintln!("Usage: devaipod server <start|stop|status>");
                std::process::exit(1);
            }
            None => {
                eprintln!("Usage: devaipod server <start|stop|status>");
                std::process::exit(1);
            }
        }
    }

    // --- Proxy all other commands into the container via podman exec ---

    // Check the container is running before trying to exec into it.
    let running = Command::new("podman")
        .args(["inspect", "--format", "{{.State.Running}}", &container_name])
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
            } else {
                None
            }
        });

    match running.as_deref() {
        Some("true") => {} // good
        Some(_) => {
            eprintln!("devaipod: container '{container_name}' is not running");
            eprintln!("Start it with: devaipod server start");
            std::process::exit(1);
        }
        None => {
            eprintln!("devaipod: container '{container_name}' not found");
            eprintln!("Start it with: devaipod server start");
            std::process::exit(1);
        }
    }

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
    cmd.arg("devaipod-server");
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
        assert_eq!(
            expand_tilde("relative/path"),
            PathBuf::from("relative/path")
        );
    }

    #[test]
    fn test_parse_start_flags_defaults() {
        let (port, image) = parse_start_flags(&[]);
        assert_eq!(port, DEFAULT_PORT);
        assert_eq!(image, None);
    }

    #[test]
    fn test_parse_start_flags_custom() {
        let args: Vec<String> = vec![
            "--port".into(),
            "9090".into(),
            "--image".into(),
            "ghcr.io/example/devaipod:v1".into(),
        ];
        let (port, image) = parse_start_flags(&args);
        assert_eq!(port, "9090");
        assert_eq!(image.as_deref(), Some("ghcr.io/example/devaipod:v1"));
    }

    #[test]
    fn test_parse_start_flags_port_only() {
        let args: Vec<String> = vec!["--port".into(), "3000".into()];
        let (port, image) = parse_start_flags(&args);
        assert_eq!(port, "3000");
        assert_eq!(image, None);
    }

    #[test]
    fn test_parse_start_flags_image_only() {
        let args: Vec<String> = vec!["--image".into(), "my-image:latest".into()];
        let (port, image) = parse_start_flags(&args);
        assert_eq!(port, DEFAULT_PORT);
        assert_eq!(image.as_deref(), Some("my-image:latest"));
    }

    #[test]
    fn test_resolve_image_default() {
        let config = Config::default();
        assert_eq!(resolve_image(None, &config), DEFAULT_IMAGE);
    }

    #[test]
    fn test_resolve_image_from_config() {
        let config = Config {
            image: Some("localhost/devaipod:dev".to_string()),
            ..Config::default()
        };
        assert_eq!(resolve_image(None, &config), "localhost/devaipod:dev");
    }

    #[test]
    fn test_resolve_image_flag_wins() {
        let config = Config {
            image: Some("localhost/devaipod:dev".to_string()),
            ..Config::default()
        };
        assert_eq!(
            resolve_image(Some("my-override:v2".to_string()), &config),
            "my-override:v2"
        );
    }

    #[test]
    fn test_host_socket_linux() {
        // When XDG_RUNTIME_DIR is set (has_xdg_runtime=true), use actual socket path
        let actual = PathBuf::from("/run/user/1000/podman/podman.sock");
        let result = host_socket_for_container(&actual, true);
        assert_eq!(result, actual);
    }

    #[test]
    fn test_host_socket_macos() {
        // Without XDG_RUNTIME_DIR (has_xdg_runtime=false), use the VM well-known path
        let actual = PathBuf::from("/some/mac/path/podman.sock");
        let result = host_socket_for_container(&actual, false);
        assert_eq!(result, PathBuf::from("/run/podman/podman.sock"));
    }
}

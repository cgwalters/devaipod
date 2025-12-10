//! gh-restricted: A wrapper around the GitHub CLI with configurable restrictions.
//!
//! This wrapper provides two modes based on configuration:
//! - Read-only mode (allow-read-all = true): Only allows read operations, no writes
//! - Restricted mode (default): Allows read operations plus scoped write operations
//!   that require state validation via upcall to the devaipod socket.
//!
//! Configuration is read from `~/.config/gh-restricted.toml`:
//! ```toml
//! # Allow all read operations without upcall validation
//! allow-read-all = true
//! ```
//!
//! Allowed write operations (restricted mode only):
//! - `pr create --draft` - Only with --draft flag, only for allowed repos
//! - `pr edit` - Only for PRs in the allowlist
//! - `pr comment` - Only for PRs in the allowlist
//!
//! Blocked operations that require human approval:
//! - `pr ready` - Marking a PR ready for review requires human decision
//! - `pr merge` - Merging requires human approval
//! - `pr close` - Closing requires human decision

use std::collections::HashSet;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::process::{Command, ExitCode, Stdio};

use serde::{Deserialize, Serialize};

use crate::config::Config;

/// Socket path for the upcall service
const UPCALL_SOCKET_PATH: &str = "/run/devaipod.sock";

/// Subcommand patterns that are allowed (read-only operations).
/// Format: "command/subcommand" or "command" for top-level commands.
const ALLOWED_READ_PATTERNS: &[&str] = &[
    // Top-level read-only commands
    "status",
    "completion",
    // Pull requests
    "pr/list",
    "pr/view",
    "pr/status",
    "pr/diff",
    "pr/checks",
    // Issues
    "issue/list",
    "issue/view",
    "issue/status",
    // Repositories
    "repo/list",
    "repo/view",
    // Releases
    "release/list",
    "release/view",
    // Actions/Workflows
    "run/list",
    "run/view",
    "run/watch",
    "workflow/list",
    "workflow/view",
    "cache/list",
    // Search (all read-only)
    "search/code",
    "search/commits",
    "search/issues",
    "search/prs",
    "search/repos",
    // Auth (read-only parts)
    "auth/status",
    "auth/token",
    // Config
    "config/get",
    "config/list",
    // Keys
    "ssh-key/list",
    "gpg-key/list",
    // Secrets/Variables (list only, not values)
    "secret/list",
    "variable/list",
    "variable/get",
    // Rulesets
    "ruleset/list",
    "ruleset/view",
    "ruleset/check",
    // Projects
    "project/list",
    "project/view",
    "project/field-list",
    "project/item-list",
    // Codespaces (read-only parts)
    "codespace/list",
    "codespace/view",
    "codespace/logs",
    // Extensions
    "extension/list",
    "extension/search",
    // Labels
    "label/list",
    // Aliases
    "alias/list",
    // Organizations
    "org/list",
    // Gists
    "gist/list",
    "gist/view",
    // Attestation
    "attestation/verify",
    // Browse (just opens URLs, doesn't modify state)
    "browse",
];

/// Restricted write patterns that require state validation.
/// Format: "command/subcommand"
const RESTRICTED_WRITE_PATTERNS: &[&str] = &[
    "pr/create",  // Only with --draft, only for allowed repos
    "pr/edit",    // Only for PRs in allowlist
    "pr/comment", // Only for PRs in allowlist
];

/// JSON-RPC 2.0 request
#[derive(Debug, Serialize, Deserialize)]
struct JsonRpcRequest {
    jsonrpc: String,
    id: serde_json::Value,
    method: String,
    #[serde(default)]
    params: serde_json::Value,
}

/// JSON-RPC 2.0 response
#[derive(Debug, Serialize, Deserialize)]
struct JsonRpcResponse {
    jsonrpc: String,
    id: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<JsonRpcError>,
}

/// JSON-RPC 2.0 error
#[derive(Debug, Serialize, Deserialize)]
struct JsonRpcError {
    code: i32,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<serde_json::Value>,
}

/// State returned from get_state upcall
#[derive(Debug, Serialize, Deserialize)]
struct AgentState {
    #[serde(default)]
    allowed_repos: Vec<String>,
    #[serde(default)]
    allowed_prs: Vec<String>,
}

/// Check if a read-only command pattern is allowed.
pub fn is_read_allowed(command: &str, subcommand: Option<&str>) -> bool {
    let allowed: HashSet<&str> = ALLOWED_READ_PATTERNS.iter().copied().collect();

    // Check "command/subcommand" pattern
    if let Some(sub) = subcommand {
        let pattern = format!("{}/{}", command, sub);
        if allowed.contains(pattern.as_str()) {
            return true;
        }
    }

    // Check top-level "command" pattern (for commands without subcommands)
    allowed.contains(command)
}

/// Check if a pattern is a restricted write operation.
fn is_restricted_write(command: &str, subcommand: Option<&str>) -> bool {
    if let Some(sub) = subcommand {
        let pattern = format!("{}/{}", command, sub);
        RESTRICTED_WRITE_PATTERNS.contains(&pattern.as_str())
    } else {
        false
    }
}

/// Parse gh arguments to extract command and subcommand.
/// Returns (command, subcommand, is_help_request)
pub fn parse_gh_args(args: &[String]) -> (Option<String>, Option<String>, bool) {
    let mut command = None;
    let mut subcommand = None;
    let mut is_help = false;
    let mut skip_next = false;

    for arg in args.iter() {
        if skip_next {
            skip_next = false;
            continue;
        }

        // Handle flags
        if arg.starts_with('-') {
            if arg == "-h" || arg == "--help" {
                is_help = true;
            }
            // Flags that take a value - skip the next arg
            if arg == "-R" || arg == "--repo" || arg == "-H" || arg == "--hostname" {
                skip_next = true;
            }
            // Also handle --flag=value format (no skip needed)
            continue;
        }

        // First non-flag is the command
        if command.is_none() {
            command = Some(arg.clone());
        } else if subcommand.is_none() {
            // Second non-flag is the subcommand
            subcommand = Some(arg.clone());
            break;
        }
    }

    (command, subcommand, is_help)
}

/// Check for dangerous flags that could turn a read-only command into a write.
pub fn has_dangerous_flags(args: &[String]) -> Option<&'static str> {
    for arg in args {
        // Input flags for gh api that imply POST
        if arg == "-f" || arg == "-F" || arg == "--input" || arg == "--raw-field" {
            return Some("Input flags (-f, -F, --input, --raw-field) are not allowed");
        }
    }
    None
}

/// Send a JSON-RPC request to the upcall socket and get the response.
fn rpc_call(method: &str, params: serde_json::Value) -> Result<serde_json::Value, String> {
    let mut stream = UnixStream::connect(UPCALL_SOCKET_PATH)
        .map_err(|e| format!("Failed to connect to upcall socket: {}", e))?;

    let request = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: serde_json::Value::Number(1.into()),
        method: method.to_string(),
        params,
    };

    let request_json = serde_json::to_string(&request)
        .map_err(|e| format!("Failed to serialize request: {}", e))?;

    writeln!(stream, "{}", request_json).map_err(|e| format!("Failed to send request: {}", e))?;
    stream
        .flush()
        .map_err(|e| format!("Failed to flush: {}", e))?;

    let mut reader = BufReader::new(stream);
    let mut response_line = String::new();
    reader
        .read_line(&mut response_line)
        .map_err(|e| format!("Failed to read response: {}", e))?;

    let response: JsonRpcResponse = serde_json::from_str(&response_line)
        .map_err(|e| format!("Failed to parse response: {}", e))?;

    if let Some(error) = response.error {
        return Err(format!("RPC error ({}): {}", error.code, error.message));
    }

    response
        .result
        .ok_or_else(|| "No result in response".to_string())
}

/// Get the agent state from the upcall service.
fn get_state() -> Result<AgentState, String> {
    let result = rpc_call("get_state", serde_json::Value::Null)?;
    serde_json::from_value(result).map_err(|e| format!("Failed to parse state: {}", e))
}

/// Check if a repo is in the allowed repos list.
pub fn is_repo_allowed(repo: &str) -> Result<bool, String> {
    let state = get_state()?;
    Ok(state.allowed_repos.iter().any(|r| r == repo))
}

/// Check if a PR URL is in the allowed PRs list.
pub fn is_pr_allowed(pr_url: &str) -> Result<bool, String> {
    let state = get_state()?;
    Ok(state.allowed_prs.iter().any(|p| p == pr_url))
}

/// Register a newly created PR with the upcall service.
pub fn register_pr(pr_url: &str) -> Result<(), String> {
    rpc_call("add_pr", serde_json::json!({ "pr_url": pr_url }))?;
    Ok(())
}

/// Extract repo from -R/--repo flag in args, or detect from git.
pub fn get_target_repo(args: &[String]) -> Result<String, String> {
    // First try to find -R or --repo in args
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == "-R" || arg == "--repo" {
            if let Some(repo) = iter.next() {
                return Ok(repo.clone());
            }
        }
        // Handle --repo=value format
        if let Some(repo) = arg.strip_prefix("--repo=") {
            return Ok(repo.to_string());
        }
        if let Some(repo) = arg.strip_prefix("-R") {
            if !repo.is_empty() {
                return Ok(repo.to_string());
            }
        }
    }

    // Fall back to detecting from git
    detect_repo_from_git()
}

/// Detect the current repo using gh repo view.
fn detect_repo_from_git() -> Result<String, String> {
    let output = Command::new("gh")
        .args([
            "repo",
            "view",
            "--json",
            "nameWithOwner",
            "-q",
            ".nameWithOwner",
        ])
        .output()
        .map_err(|e| format!("Failed to run gh repo view: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "Failed to detect repo: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let repo = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if repo.is_empty() {
        return Err("Could not detect repository".to_string());
    }
    Ok(repo)
}

/// Extract PR identifier from args (number or URL).
/// Returns the first positional argument that looks like a PR reference.
pub fn get_pr_identifier(args: &[String]) -> Option<String> {
    let mut skip_next = false;

    for arg in args.iter() {
        if skip_next {
            skip_next = false;
            continue;
        }

        // Skip flags
        if arg.starts_with('-') {
            // Flags that take a value
            if arg == "-R"
                || arg == "--repo"
                || arg == "-H"
                || arg == "--hostname"
                || arg == "-b"
                || arg == "--body"
                || arg == "-F"
                || arg == "--body-file"
                || arg == "-t"
                || arg == "--title"
            {
                skip_next = true;
            }
            continue;
        }

        // Skip command and subcommand (pr, edit/ready/comment)
        if arg == "pr" || arg == "edit" || arg == "ready" || arg == "comment" {
            continue;
        }

        // This should be the PR identifier
        return Some(arg.clone());
    }

    None
}

/// Convert a PR identifier (number or URL) to a full PR URL.
fn pr_identifier_to_url(identifier: &str, repo: &str) -> String {
    // If it's already a URL, return it
    if identifier.starts_with("https://") || identifier.starts_with("http://") {
        return identifier.to_string();
    }

    // Otherwise assume it's a PR number
    format!("https://github.com/{}/pull/{}", repo, identifier)
}

/// Check if --draft flag is present in args.
fn has_draft_flag(args: &[String]) -> bool {
    args.iter().any(|a| a == "--draft" || a == "-d")
}

/// Run gh and capture stdout.
fn run_gh_capture(args: &[String]) -> Result<(ExitCode, String), String> {
    let child = Command::new("gh")
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| format!("Failed to run gh: {}", e))?;

    let output = child
        .wait_with_output()
        .map_err(|e| format!("Failed to wait for gh: {}", e))?;

    let exit_code = if let Some(code) = output.status.code() {
        ExitCode::from(code as u8)
    } else {
        ExitCode::from(1)
    };

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    // Print stdout so user sees it
    print!("{}", stdout);

    Ok((exit_code, stdout))
}

/// Run gh normally (pass through).
fn run_gh(args: &[String]) -> ExitCode {
    let status = Command::new("gh").args(args).status();

    match status {
        Ok(s) => {
            if let Some(code) = s.code() {
                ExitCode::from(code as u8)
            } else {
                ExitCode::from(1)
            }
        }
        Err(e) => {
            eprintln!("error: failed to run gh: {}", e);
            ExitCode::from(1)
        }
    }
}

/// Extract PR URL from gh pr create output.
/// gh typically outputs the PR URL on the last line.
fn extract_pr_url(output: &str) -> Option<String> {
    for line in output.lines().rev() {
        let trimmed = line.trim();
        if trimmed.starts_with("https://github.com/") && trimmed.contains("/pull/") {
            return Some(trimmed.to_string());
        }
    }
    None
}

/// Handle pr create command.
fn handle_pr_create(args: &[String]) -> ExitCode {
    // Must have --draft flag
    if !has_draft_flag(args) {
        eprintln!("error: 'gh pr create' requires --draft flag in restricted mode");
        eprintln!("Add --draft to create a draft pull request");
        return ExitCode::from(1);
    }

    // Get target repo
    let repo = match get_target_repo(args) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: {}", e);
            return ExitCode::from(1);
        }
    };

    // Check if repo is allowed
    match is_repo_allowed(&repo) {
        Ok(true) => {}
        Ok(false) => {
            eprintln!("error: repository '{}' is not in the allowed list", repo);
            return ExitCode::from(1);
        }
        Err(e) => {
            eprintln!("error: failed to check repo permissions: {}", e);
            return ExitCode::from(1);
        }
    }

    // Run gh pr create and capture output
    let (exit_code, stdout) = match run_gh_capture(args) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: {}", e);
            return ExitCode::from(1);
        }
    };

    // If successful, register the PR
    if exit_code == ExitCode::SUCCESS {
        if let Some(pr_url) = extract_pr_url(&stdout) {
            if let Err(e) = register_pr(&pr_url) {
                eprintln!("warning: failed to register PR: {}", e);
                // Don't fail the command, the PR was created
            }
        }
    }

    exit_code
}

/// Handle pr edit/ready/comment commands.
fn handle_pr_modify(args: &[String], subcommand: &str) -> ExitCode {
    // Get target repo
    let repo = match get_target_repo(args) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: {}", e);
            return ExitCode::from(1);
        }
    };

    // Get PR identifier
    let pr_id = match get_pr_identifier(args) {
        Some(id) => id,
        None => {
            eprintln!("error: could not find PR identifier in arguments");
            return ExitCode::from(1);
        }
    };

    // Convert to full URL
    let pr_url = pr_identifier_to_url(&pr_id, &repo);

    // Check if PR is allowed
    match is_pr_allowed(&pr_url) {
        Ok(true) => {}
        Ok(false) => {
            eprintln!(
                "error: PR '{}' is not in the allowed list for {} operation",
                pr_url, subcommand
            );
            return ExitCode::from(1);
        }
        Err(e) => {
            eprintln!("error: failed to check PR permissions: {}", e);
            return ExitCode::from(1);
        }
    }

    // Run the command
    run_gh(args)
}

/// Run gh-restricted with the given arguments.
pub fn run(args: Vec<String>) -> ExitCode {
    let config = Config::load();

    // Handle our own --help
    if (args.is_empty() || args.iter().any(|a| a == "--help" || a == "-h"))
        && (args.len() <= 1 || args[0] == "--help" || args[0] == "-h")
    {
        print_help(&config);
        return ExitCode::SUCCESS;
    }

    let (command, subcommand, is_help) = parse_gh_args(&args);

    // If just asking for help on a specific command, allow it
    if is_help {
        return run_gh(&args);
    }

    let Some(cmd) = command else {
        print_help(&config);
        return ExitCode::SUCCESS;
    };

    // Block 'api' command entirely
    if cmd == "api" {
        eprintln!("error: 'gh api' is not allowed in restricted mode");
        eprintln!("Use specific gh commands like 'gh pr list' instead");
        return ExitCode::from(1);
    }

    // Check for dangerous flags
    if let Some(reason) = has_dangerous_flags(&args) {
        eprintln!("error: {}", reason);
        return ExitCode::from(1);
    }

    // In read-only mode (allow-read-all = true), only allow read operations
    if config.allow_read_all {
        // Check if the command is in the read-only allowlist
        if is_read_allowed(&cmd, subcommand.as_deref()) {
            return run_gh(&args);
        }

        // Not in read-only allowlist - reject
        let full_cmd = match &subcommand {
            Some(sub) => format!("gh {} {}", cmd, sub),
            None => format!("gh {}", cmd),
        };
        eprintln!("error: '{}' is not allowed in read-only mode", full_cmd);
        eprintln!();
        eprintln!("Allowed read-only commands include:");
        eprintln!("  gh pr list, gh pr view, gh pr status, gh pr diff, gh pr checks");
        eprintln!("  gh issue list, gh issue view, gh issue status");
        eprintln!("  gh repo list, gh repo view");
        eprintln!("  gh search issues, gh search prs, gh search repos");
        eprintln!("  gh run list, gh run view, gh workflow list");
        eprintln!("  ... and more (see gh-restricted --help)");
        return ExitCode::from(1);
    }

    // Restricted mode (default): allow reads + scoped writes

    // Check if this is a restricted write operation
    if is_restricted_write(&cmd, subcommand.as_deref()) {
        let sub = subcommand.as_deref().unwrap();
        return match (cmd.as_str(), sub) {
            ("pr", "create") => handle_pr_create(&args),
            ("pr", "edit") | ("pr", "comment") => handle_pr_modify(&args, sub),
            _ => {
                eprintln!("error: unhandled restricted write operation");
                ExitCode::from(1)
            }
        };
    }

    // Block pr ready - requires human approval
    if cmd == "pr" && subcommand.as_deref() == Some("ready") {
        eprintln!("error: 'gh pr ready' requires human approval");
        eprintln!("Marking a PR as ready for review is a human decision.");
        eprintln!("Use 'gh pr ready' from outside the sandbox.");
        return ExitCode::from(1);
    }

    // Check if the command is in the read-only allowlist
    if !is_read_allowed(&cmd, subcommand.as_deref()) {
        let full_cmd = match &subcommand {
            Some(sub) => format!("gh {} {}", cmd, sub),
            None => format!("gh {}", cmd),
        };
        eprintln!("error: '{}' is not allowed in restricted mode", full_cmd);
        eprintln!();
        eprintln!("Allowed read-only commands include:");
        eprintln!("  gh pr list, gh pr view, gh pr status, gh pr diff, gh pr checks");
        eprintln!("  gh issue list, gh issue view, gh issue status");
        eprintln!("  ... and more (see gh-restricted --help)");
        eprintln!();
        eprintln!("Allowed restricted write operations:");
        eprintln!("  gh pr create --draft  (for allowed repos only)");
        eprintln!("  gh pr edit, gh pr comment  (for allowed PRs only)");
        return ExitCode::from(1);
    }

    // All checks passed, run the real gh
    run_gh(&args)
}

/// Print help for gh-restricted
pub fn print_help(config: &Config) {
    println!("gh-restricted - Configurable GitHub CLI wrapper for devaipod");
    println!();
    println!("USAGE:");
    println!("    gh-restricted <command> [subcommand] [options]");
    println!();
    println!("DESCRIPTION:");
    println!("    A restricted wrapper around the GitHub CLI (gh) with configurable");
    println!("    access levels. Designed for sandboxed AI agents.");
    println!();
    println!("CONFIGURATION:");
    println!("    Config file: ~/.config/gh-restricted.toml");
    println!();
    println!("    Example:");
    println!("      # Read-only mode (no writes allowed)");
    println!("      allow-read-all = true");
    println!();
    println!(
        "CURRENT MODE: {}",
        if config.allow_read_all {
            "read-only"
        } else {
            "restricted"
        }
    );
    println!();
    println!("READ-ONLY COMMANDS:");
    println!();
    println!("  Pull Requests:");
    println!("    pr list        List pull requests");
    println!("    pr view        View a pull request");
    println!("    pr status      Show PR status for current branch");
    println!("    pr diff        View PR diff");
    println!("    pr checks      View PR checks/CI status");
    println!();
    println!("  Issues:");
    println!("    issue list     List issues");
    println!("    issue view     View an issue");
    println!("    issue status   Show issue status");
    println!();
    println!("  Repositories:");
    println!("    repo list      List repositories");
    println!("    repo view      View repository info");
    println!();
    println!("  Search:");
    println!("    search code    Search code");
    println!("    search commits Search commits");
    println!("    search issues  Search issues");
    println!("    search prs     Search pull requests");
    println!("    search repos   Search repositories");
    println!();
    println!("  Actions/Workflows:");
    println!("    run list       List workflow runs");
    println!("    run view       View a workflow run");
    println!("    run watch      Watch a workflow run");
    println!("    workflow list  List workflows");
    println!("    workflow view  View a workflow");
    println!("    cache list     List Actions caches");
    println!();
    println!("  Releases:");
    println!("    release list   List releases");
    println!("    release view   View a release");
    println!();
    println!("  Other:");
    println!("    status         Show cross-repo status");
    println!("    browse         Open repo in browser");
    println!("    gist list      List gists");
    println!("    gist view      View a gist");
    println!("    label list     List labels");
    println!("    org list       List organizations");
    println!("    project list   List projects");
    println!("    project view   View a project");

    if !config.allow_read_all {
        println!();
        println!("RESTRICTED WRITE OPERATIONS (requires upcall validation):");
        println!();
        println!("  Pull Requests:");
        println!("    pr create --draft    Create a draft PR (requires --draft flag)");
        println!("                         Only for repos in the allowed_repos list");
        println!("                         Newly created PRs are auto-registered");
        println!();
        println!("    pr edit <number>     Edit an existing PR");
        println!("                         Only for PRs in the allowed_prs list");
        println!();
        println!("    pr comment <number>  Add a comment to a PR");
        println!("                         Only for PRs in the allowed_prs list");
        println!();
        println!("REQUIRES HUMAN APPROVAL:");
        println!();
        println!("    pr ready             Marking a PR ready for review requires human decision");
        println!("    pr merge             Merging a PR requires human approval");
        println!("    pr close             Closing a PR requires human decision");
        println!();
        println!("STATE VALIDATION:");
        println!("    Write operations require validation via /run/devaipod.sock");
        println!("    - get_state: Returns allowed_repos and allowed_prs lists");
        println!("    - add_pr: Registers a newly created PR");
    }

    println!();
    println!("BLOCKED:");
    println!("    All other write operations (merge, close, delete, etc.)");
    println!("    The 'gh api' command is entirely blocked.");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_allowed_commands() {
        assert!(is_read_allowed("pr", Some("list")));
        assert!(is_read_allowed("pr", Some("view")));
        assert!(is_read_allowed("pr", Some("status")));
        assert!(is_read_allowed("pr", Some("diff")));
        assert!(is_read_allowed("pr", Some("checks")));
        assert!(is_read_allowed("issue", Some("list")));
        assert!(is_read_allowed("issue", Some("view")));
        assert!(is_read_allowed("status", None));
        assert!(is_read_allowed("browse", None));
        assert!(is_read_allowed("search", Some("issues")));
        assert!(is_read_allowed("search", Some("prs")));
    }

    #[test]
    fn test_read_blocked_commands() {
        assert!(!is_read_allowed("pr", Some("create")));
        assert!(!is_read_allowed("pr", Some("merge")));
        assert!(!is_read_allowed("pr", Some("close")));
        assert!(!is_read_allowed("pr", Some("edit")));
        assert!(!is_read_allowed("pr", Some("comment")));
        assert!(!is_read_allowed("pr", Some("review")));
        assert!(!is_read_allowed("issue", Some("create")));
        assert!(!is_read_allowed("issue", Some("close")));
        assert!(!is_read_allowed("issue", Some("delete")));
        assert!(!is_read_allowed("repo", Some("create")));
        assert!(!is_read_allowed("repo", Some("delete")));
        assert!(!is_read_allowed("repo", Some("fork")));
        assert!(!is_read_allowed("api", None));
        assert!(!is_read_allowed("api", Some("repos")));
    }

    #[test]
    fn test_is_restricted_write() {
        assert!(is_restricted_write("pr", Some("create")));
        assert!(is_restricted_write("pr", Some("edit")));
        assert!(is_restricted_write("pr", Some("comment")));
        // pr ready requires human approval, not in restricted writes
        assert!(!is_restricted_write("pr", Some("ready")));
        assert!(!is_restricted_write("pr", Some("list")));
        assert!(!is_restricted_write("pr", Some("merge")));
        assert!(!is_restricted_write("pr", None));
    }

    #[test]
    fn test_parse_args_simple() {
        let args = vec!["pr".to_string(), "list".to_string()];
        let (cmd, sub, help) = parse_gh_args(&args);
        assert_eq!(cmd, Some("pr".to_string()));
        assert_eq!(sub, Some("list".to_string()));
        assert!(!help);
    }

    #[test]
    fn test_parse_args_with_flags() {
        // -R flag with value should be skipped
        let args = vec![
            "-R".to_string(),
            "owner/repo".to_string(),
            "pr".to_string(),
            "list".to_string(),
        ];
        let (cmd, sub, _) = parse_gh_args(&args);
        assert_eq!(cmd, Some("pr".to_string()));
        assert_eq!(sub, Some("list".to_string()));
    }

    #[test]
    fn test_parse_args_help() {
        let args = vec!["--help".to_string()];
        let (cmd, sub, help) = parse_gh_args(&args);
        assert_eq!(cmd, None);
        assert_eq!(sub, None);
        assert!(help);

        let args = vec!["pr".to_string(), "--help".to_string()];
        let (cmd, _sub, help) = parse_gh_args(&args);
        assert_eq!(cmd, Some("pr".to_string()));
        assert!(help);
    }

    #[test]
    fn test_dangerous_flags() {
        assert!(has_dangerous_flags(&vec!["-f".to_string(), "foo=bar".to_string()]).is_some());
        assert!(has_dangerous_flags(&vec!["-F".to_string(), "foo=@file".to_string()]).is_some());
        assert!(
            has_dangerous_flags(&vec!["--input".to_string(), "file.json".to_string()]).is_some()
        );
        assert!(has_dangerous_flags(&vec!["pr".to_string(), "list".to_string()]).is_none());
    }

    #[test]
    fn test_has_draft_flag() {
        assert!(has_draft_flag(&vec![
            "pr".into(),
            "create".into(),
            "--draft".into()
        ]));
        assert!(has_draft_flag(&vec![
            "pr".into(),
            "create".into(),
            "-d".into()
        ]));
        assert!(!has_draft_flag(&vec!["pr".into(), "create".into()]));
    }

    #[test]
    fn test_get_target_repo_from_args() {
        let args = vec![
            "-R".into(),
            "owner/repo".into(),
            "pr".into(),
            "create".into(),
        ];
        assert_eq!(get_target_repo(&args).unwrap(), "owner/repo");

        let args = vec![
            "--repo".into(),
            "foo/bar".into(),
            "pr".into(),
            "list".into(),
        ];
        assert_eq!(get_target_repo(&args).unwrap(), "foo/bar");

        let args = vec!["--repo=baz/qux".into(), "pr".into(), "view".into()];
        assert_eq!(get_target_repo(&args).unwrap(), "baz/qux");
    }

    #[test]
    fn test_get_pr_identifier() {
        let args = vec!["pr".into(), "edit".into(), "42".into()];
        assert_eq!(get_pr_identifier(&args), Some("42".into()));

        let args = vec![
            "pr".into(),
            "ready".into(),
            "123".into(),
            "--confirm".into(),
        ];
        assert_eq!(get_pr_identifier(&args), Some("123".into()));

        let args = vec![
            "-R".into(),
            "owner/repo".into(),
            "pr".into(),
            "comment".into(),
            "99".into(),
            "-b".into(),
            "message".into(),
        ];
        assert_eq!(get_pr_identifier(&args), Some("99".into()));

        let args = vec!["pr".into(), "comment".into()];
        assert_eq!(get_pr_identifier(&args), None);
    }

    #[test]
    fn test_pr_identifier_to_url() {
        assert_eq!(
            pr_identifier_to_url("42", "owner/repo"),
            "https://github.com/owner/repo/pull/42"
        );
        assert_eq!(
            pr_identifier_to_url("https://github.com/foo/bar/pull/123", "ignored"),
            "https://github.com/foo/bar/pull/123"
        );
    }

    #[test]
    fn test_extract_pr_url() {
        let output =
            "Creating pull request for feature-branch\nhttps://github.com/owner/repo/pull/42\n";
        assert_eq!(
            extract_pr_url(output),
            Some("https://github.com/owner/repo/pull/42".to_string())
        );

        let output = "Some other output";
        assert_eq!(extract_pr_url(output), None);
    }
}

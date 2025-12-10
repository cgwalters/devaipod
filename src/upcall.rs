//! Upcall RPC mechanism for controlled operations from the sandbox.
//!
//! The sandbox runs with minimal privileges, but sometimes needs to perform
//! operations that require access outside the sandbox (like creating a GitHub PR).
//!
//! This module implements a JSON-RPC 2.0 service:
//! 1. The sandbox connects to a Unix socket exposed by the host
//! 2. It sends a JSON-RPC request to execute an allowlisted binary
//! 3. The host validates the binary is in the allowlist and executes it
//! 4. The host sends back a JSON-RPC response with output and exit code
//!
//! # Security Model
//!
//! - Only binaries present in `/usr/lib/devaipod/upcalls/` can be executed
//! - Binary names must not contain path separators
//! - Commands run in the workspace directory (`/workspaces/<name>`)
//! - All operations are logged for audit

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::Command as ProcessCommand;

use color_eyre::eyre::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::state;

/// Socket path for the upcall service
pub const UPCALL_SOCKET_PATH: &str = "/run/devaipod.sock";

/// Directory containing allowlisted binaries (can be symlinks)
pub const UPCALL_BINARIES_DIR: &str = "/usr/lib/devaipod/upcalls";

/// JSON-RPC 2.0 request
#[derive(Debug, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    /// JSON-RPC version (must be "2.0")
    pub jsonrpc: String,
    /// Request ID
    pub id: serde_json::Value,
    /// Method name
    pub method: String,
    /// Method parameters
    #[serde(default)]
    pub params: serde_json::Value,
}

/// JSON-RPC 2.0 successful response
#[derive(Debug, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    /// JSON-RPC version (always "2.0")
    pub jsonrpc: String,
    /// Request ID (echoed from request)
    pub id: serde_json::Value,
    /// Result (present on success)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    /// Error (present on failure)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

/// JSON-RPC 2.0 error object
#[derive(Debug, Serialize, Deserialize)]
pub struct JsonRpcError {
    /// Error code
    pub code: i32,
    /// Error message
    pub message: String,
    /// Additional error data
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

/// Parameters for the "exec" method
#[derive(Debug, Serialize, Deserialize)]
pub struct ExecParams {
    /// Binary name (must exist in UPCALL_BINARIES_DIR)
    pub binary: String,
    /// Arguments to pass to the binary
    #[serde(default)]
    pub args: Vec<String>,
}

/// Result of the "exec" method
#[derive(Debug, Serialize, Deserialize)]
pub struct ExecResult {
    /// Exit code of the process
    pub exit_code: i32,
    /// Combined stdout and stderr output
    pub output: String,
}

/// Parameters for the "add_pr" method
#[derive(Debug, Serialize, Deserialize)]
pub struct AddPrParams {
    /// PR URL (https://github.com/owner/repo/pull/123)
    pub pr_url: String,
}

// JSON-RPC error codes
const JSONRPC_PARSE_ERROR: i32 = -32700;
const JSONRPC_INVALID_REQUEST: i32 = -32600;
const JSONRPC_METHOD_NOT_FOUND: i32 = -32601;
const JSONRPC_INVALID_PARAMS: i32 = -32602;
const JSONRPC_SERVER_ERROR: i32 = -32000;

impl JsonRpcResponse {
    /// Create a successful response
    fn success(id: serde_json::Value, result: serde_json::Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: Some(result),
            error: None,
        }
    }

    /// Create an error response
    fn error(id: serde_json::Value, code: i32, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: None,
            error: Some(JsonRpcError {
                code,
                message: message.into(),
                data: None,
            }),
        }
    }

    /// Create a parse error response (null id since we couldn't parse the request)
    fn parse_error(message: impl Into<String>) -> Self {
        Self::error(serde_json::Value::Null, JSONRPC_PARSE_ERROR, message)
    }
}

/// Check if a binary is in the allowlist.
///
/// A binary is allowed if a file (or symlink) with that name exists in
/// `UPCALL_BINARIES_DIR`.
pub fn is_binary_allowed(binary: &str) -> bool {
    // Security: reject any path separators to prevent directory traversal
    if binary.contains('/') || binary.contains('\\') {
        return false;
    }

    // Security: reject empty binary names
    if binary.is_empty() {
        return false;
    }

    // Check if the binary exists in the allowlist directory
    let binary_path = Path::new(UPCALL_BINARIES_DIR).join(binary);
    binary_path.exists()
}

/// Get the full path to an allowlisted binary.
///
/// Returns `None` if the binary is not allowed.
fn get_binary_path(binary: &str) -> Option<std::path::PathBuf> {
    if !is_binary_allowed(binary) {
        return None;
    }
    Some(Path::new(UPCALL_BINARIES_DIR).join(binary))
}

/// Execute a command and return the exit code and combined output.
///
/// This is used by the server side to execute allowlisted binaries.
fn execute_binary(
    binary: &str,
    args: &[String],
    workspace: &str,
) -> std::result::Result<ExecResult, String> {
    let binary_path =
        get_binary_path(binary).ok_or_else(|| format!("Binary '{}' not in allowlist", binary))?;

    let workspace_path = format!("/workspaces/{}", workspace);

    tracing::info!(
        "Executing: {:?} {:?} in {}",
        binary_path,
        args,
        workspace_path
    );

    let output = ProcessCommand::new(&binary_path)
        .args(args)
        .current_dir(&workspace_path)
        .output()
        .map_err(|e| format!("Failed to execute '{}': {}", binary, e))?;

    let exit_code = output.status.code().unwrap_or(-1);

    // Combine stdout and stderr
    let mut combined = String::new();
    combined.push_str(&String::from_utf8_lossy(&output.stdout));
    combined.push_str(&String::from_utf8_lossy(&output.stderr));

    Ok(ExecResult {
        exit_code,
        output: combined,
    })
}

/// Handle a single JSON-RPC request.
fn handle_request(request: &JsonRpcRequest, workspace: &str) -> JsonRpcResponse {
    // Validate JSON-RPC version
    if request.jsonrpc != "2.0" {
        return JsonRpcResponse::error(
            request.id.clone(),
            JSONRPC_INVALID_REQUEST,
            "Invalid JSON-RPC version (must be \"2.0\")",
        );
    }

    match request.method.as_str() {
        "exec" => handle_exec(request, workspace),
        "get_state" => handle_get_state(request),
        // Note: add_repo and remove_repo are intentionally NOT exposed via RPC.
        // The agent should not be able to modify its own repo allowlist.
        // Use `devaipod upcall add-repo` from outside the sandbox instead.
        "add_pr" => handle_add_pr(request),
        _ => JsonRpcResponse::error(
            request.id.clone(),
            JSONRPC_METHOD_NOT_FOUND,
            format!("Method '{}' not found", request.method),
        ),
    }
}

/// Handle the "exec" method.
fn handle_exec(request: &JsonRpcRequest, workspace: &str) -> JsonRpcResponse {
    // Parse the exec parameters
    let params: ExecParams = match serde_json::from_value(request.params.clone()) {
        Ok(p) => p,
        Err(e) => {
            return JsonRpcResponse::error(
                request.id.clone(),
                JSONRPC_INVALID_PARAMS,
                format!("Invalid params: {}", e),
            );
        }
    };

    // Check if the binary is allowed
    if !is_binary_allowed(&params.binary) {
        return JsonRpcResponse::error(
            request.id.clone(),
            JSONRPC_SERVER_ERROR,
            format!("Binary '{}' not in allowlist", params.binary),
        );
    }

    // Execute the binary
    match execute_binary(&params.binary, &params.args, workspace) {
        Ok(result) => {
            let result_json = serde_json::to_value(result).unwrap_or(serde_json::Value::Null);
            JsonRpcResponse::success(request.id.clone(), result_json)
        }
        Err(e) => JsonRpcResponse::error(request.id.clone(), JSONRPC_SERVER_ERROR, e),
    }
}

/// Handle the "get_state" method.
fn handle_get_state(request: &JsonRpcRequest) -> JsonRpcResponse {
    match state::load_state() {
        Ok(state) => {
            let result_json = serde_json::to_value(state).unwrap_or(serde_json::Value::Null);
            JsonRpcResponse::success(request.id.clone(), result_json)
        }
        Err(e) => JsonRpcResponse::error(
            request.id.clone(),
            JSONRPC_SERVER_ERROR,
            format!("Failed to load state: {}", e),
        ),
    }
}

// Note: add_repo and remove_repo are intentionally NOT exposed via RPC.
// The agent should not be able to modify its own repo allowlist.
// These operations are done via CLI: `devaipod upcall add-repo <repo>`

/// Handle the "add_pr" method.
fn handle_add_pr(request: &JsonRpcRequest) -> JsonRpcResponse {
    let params: AddPrParams = match serde_json::from_value(request.params.clone()) {
        Ok(p) => p,
        Err(e) => {
            return JsonRpcResponse::error(
                request.id.clone(),
                JSONRPC_INVALID_PARAMS,
                format!("Invalid params: {}", e),
            );
        }
    };

    match state::add_pr(&params.pr_url) {
        Ok(()) => JsonRpcResponse::success(request.id.clone(), serde_json::json!({"ok": true})),
        Err(e) => JsonRpcResponse::error(
            request.id.clone(),
            JSONRPC_SERVER_ERROR,
            format!("Failed to add PR: {}", e),
        ),
    }
}

/// Handle a single upcall connection.
///
/// Reads a JSON-RPC request from the stream, processes it, and writes the response.
pub fn handle_connection(stream: UnixStream, workspace: &str) -> Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut writer = stream;

    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;

    // Handle empty requests (e.g., shutdown signal)
    if request_line.trim().is_empty() {
        return Ok(());
    }

    let response = match serde_json::from_str::<JsonRpcRequest>(&request_line) {
        Ok(request) => {
            tracing::info!("Received JSON-RPC request: method={}", request.method);
            handle_request(&request, workspace)
        }
        Err(e) => {
            tracing::warn!("Failed to parse JSON-RPC request: {}", e);
            JsonRpcResponse::parse_error(format!("Parse error: {}", e))
        }
    };

    let response_json = serde_json::to_string(&response)?;
    writeln!(writer, "{}", response_json)?;
    writer.flush()?;

    Ok(())
}

/// Execute a command via the upcall RPC (client-side helper).
///
/// This is called from inside the sandbox to request execution of an
/// allowlisted binary on the host.
pub fn exec_command(binary: &str, args: &[&str]) -> Result<(i32, String)> {
    let socket_path = Path::new(UPCALL_SOCKET_PATH);
    if !socket_path.exists() {
        bail!(
            "Upcall socket not found at {}. Are you running inside a devaipod sandbox?",
            UPCALL_SOCKET_PATH
        );
    }

    let mut stream =
        UnixStream::connect(socket_path).context("Failed to connect to upcall socket")?;

    // Build the JSON-RPC request
    let request = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: serde_json::Value::Number(1.into()),
        method: "exec".to_string(),
        params: serde_json::json!({
            "binary": binary,
            "args": args,
        }),
    };

    let request_json = serde_json::to_string(&request).context("Failed to serialize request")?;
    writeln!(stream, "{}", request_json).context("Failed to send request")?;
    stream.flush()?;

    let mut reader = BufReader::new(stream);
    let mut response_line = String::new();
    reader
        .read_line(&mut response_line)
        .context("Failed to read response")?;

    let response: JsonRpcResponse =
        serde_json::from_str(&response_line).context("Failed to parse response")?;

    if let Some(error) = response.error {
        bail!("RPC error ({}): {}", error.code, error.message);
    }

    let result: ExecResult = serde_json::from_value(
        response
            .result
            .ok_or_else(|| color_eyre::eyre::eyre!("No result in response"))?,
    )
    .context("Failed to parse exec result")?;

    Ok((result.exit_code, result.output))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_binary_allowed_rejects_path_separators() {
        assert!(!is_binary_allowed("../evil"));
        assert!(!is_binary_allowed("/bin/sh"));
        assert!(!is_binary_allowed("foo/bar"));
        assert!(!is_binary_allowed("..\\evil"));
    }

    #[test]
    fn test_is_binary_allowed_rejects_empty() {
        assert!(!is_binary_allowed(""));
    }

    #[test]
    fn test_jsonrpc_request_parsing() {
        let json = r#"{"jsonrpc": "2.0", "id": 1, "method": "exec", "params": {"binary": "gh", "args": ["pr", "create"]}}"#;
        let request: JsonRpcRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.jsonrpc, "2.0");
        assert_eq!(request.method, "exec");

        let params: ExecParams = serde_json::from_value(request.params).unwrap();
        assert_eq!(params.binary, "gh");
        assert_eq!(params.args, vec!["pr", "create"]);
    }

    #[test]
    fn test_jsonrpc_response_success() {
        let response = JsonRpcResponse::success(
            serde_json::Value::Number(1.into()),
            serde_json::json!({"exit_code": 0, "output": "hello"}),
        );
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"jsonrpc\":\"2.0\""));
        assert!(json.contains("\"result\""));
        assert!(!json.contains("\"error\""));
    }

    #[test]
    fn test_jsonrpc_response_error() {
        let response = JsonRpcResponse::error(
            serde_json::Value::Number(1.into()),
            JSONRPC_SERVER_ERROR,
            "Binary 'foo' not in allowlist",
        );
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"error\""));
        assert!(json.contains("-32000"));
        assert!(json.contains("not in allowlist"));
        assert!(!json.contains("\"result\""));
    }

    #[test]
    fn test_exec_params_default_args() {
        let json = r#"{"binary": "gh"}"#;
        let params: ExecParams = serde_json::from_str(json).unwrap();
        assert_eq!(params.binary, "gh");
        assert!(params.args.is_empty());
    }

    #[test]
    fn test_handle_request_method_not_found() {
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: serde_json::Value::Number(1.into()),
            method: "unknown".to_string(),
            params: serde_json::Value::Null,
        };
        let response = handle_request(&request, "test");
        assert!(response.error.is_some());
        assert_eq!(response.error.unwrap().code, JSONRPC_METHOD_NOT_FOUND);
    }

    #[test]
    fn test_handle_request_invalid_version() {
        let request = JsonRpcRequest {
            jsonrpc: "1.0".to_string(),
            id: serde_json::Value::Number(1.into()),
            method: "exec".to_string(),
            params: serde_json::Value::Null,
        };
        let response = handle_request(&request, "test");
        assert!(response.error.is_some());
        assert_eq!(response.error.unwrap().code, JSONRPC_INVALID_REQUEST);
    }

    #[test]
    fn test_handle_exec_invalid_params() {
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: serde_json::Value::Number(1.into()),
            method: "exec".to_string(),
            params: serde_json::json!({"not_binary": "gh"}),
        };
        let response = handle_request(&request, "test");
        assert!(response.error.is_some());
        assert_eq!(response.error.unwrap().code, JSONRPC_INVALID_PARAMS);
    }

    #[test]
    fn test_handle_exec_binary_not_allowed() {
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: serde_json::Value::Number(1.into()),
            method: "exec".to_string(),
            params: serde_json::json!({"binary": "nonexistent_binary_xyz"}),
        };
        let response = handle_request(&request, "test");
        assert!(response.error.is_some());
        let error = response.error.unwrap();
        assert_eq!(error.code, JSONRPC_SERVER_ERROR);
        assert!(error.message.contains("not in allowlist"));
    }
}

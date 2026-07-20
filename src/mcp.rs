//! MCP (Model Context Protocol) server for advisor tools.
//!
//! Implements the Streamable HTTP transport (JSON-RPC over HTTP POST)
//! at `/api/devaipod/mcp`. Provides pod introspection and draft proposal
//! management tools for the advisor agent.

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::advisor;

/// JSON-RPC request envelope.
#[derive(Debug, Deserialize)]
pub struct JsonRpcRequest {
    #[allow(dead_code)]
    jsonrpc: String,
    #[serde(default)]
    id: Option<Value>,
    method: String,
    #[serde(default)]
    params: Option<Value>,
}

/// Handle an MCP JSON-RPC request.
///
/// Notifications (no `id`) get 202 Accepted. Requests with an `id` get a
/// JSON-RPC response with `result` or `error`.
pub async fn handle_mcp(Json(req): Json<JsonRpcRequest>) -> Response {
    // Notifications (no id) get 202
    if req.id.is_none() {
        return StatusCode::ACCEPTED.into_response();
    }

    let id = req.id.unwrap();

    let result = match req.method.as_str() {
        "initialize" => Ok(handle_initialize()),
        "ping" => Ok(json!({})),
        "tools/list" => Ok(handle_tools_list()),
        "tools/call" => handle_tools_call(req.params).await,
        _ => Err(json_rpc_error(-32601, "Method not found")),
    };

    match result {
        Ok(result) => Json(json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": result
        }))
        .into_response(),
        Err(error) => Json(json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": error
        }))
        .into_response(),
    }
}

fn json_rpc_error(code: i32, message: &str) -> Value {
    json!({ "code": code, "message": message })
}

fn handle_initialize() -> Value {
    json!({
        "protocolVersion": "2025-03-26",
        "capabilities": {
            "tools": {}
        },
        "serverInfo": {
            "name": "devaipod",
            "version": env!("CARGO_PKG_VERSION")
        }
    })
}

fn handle_tools_list() -> Value {
    json!({
        "tools": [
            {
                "name": "list_pods",
                "description": "List all devaipod pods with their status, task, and age",
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                    "required": []
                }
            },
            {
                "name": "pod_status",
                "description": "Get detailed status for a specific devaipod pod including container states",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "pod_name": {
                            "type": "string",
                            "description": "Name of the pod (with or without 'devaipod-' prefix)"
                        }
                    },
                    "required": ["pod_name"]
                }
            },
            {
                "name": "pod_logs",
                "description": "Get recent logs from a pod's agent container",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "pod_name": {
                            "type": "string",
                            "description": "Name of the pod"
                        },
                        "lines": {
                            "type": "integer",
                            "description": "Number of log lines to return (default: 100)"
                        }
                    },
                    "required": ["pod_name"]
                }
            },
            {
                "name": "propose_agent",
                "description": "Create a draft proposal for launching a new agent pod. The proposal is inert until a human approves it.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "title": {
                            "type": "string",
                            "description": "Human-readable summary of the proposed task"
                        },
                        "repo": {
                            "type": "string",
                            "description": "Target repository (e.g. 'myorg/backend')"
                        },
                        "task": {
                            "type": "string",
                            "description": "Detailed task description for the agent"
                        },
                        "rationale": {
                            "type": "string",
                            "description": "Why this task is worth doing"
                        },
                        "priority": {
                            "type": "string",
                            "enum": ["high", "medium", "low"],
                            "description": "Priority level"
                        },
                        "source": {
                            "type": "string",
                            "description": "What triggered this proposal (e.g. 'github:myorg/backend#142')"
                        }
                    },
                    "required": ["title", "repo", "task", "rationale", "priority"]
                }
            },
            {
                "name": "list_proposals",
                "description": "List current draft proposals and their status",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "status": {
                            "type": "string",
                            "enum": ["pending", "approved", "dismissed", "expired"],
                            "description": "Filter by status (default: all)"
                        }
                    }
                }
            },
            {
                "name": "list_workspaces",
                "description": "List all agent workspaces with their state, source repos, git branches, completion status, and commit counts. This gives a comprehensive view of all active and completed agent work.",
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                    "required": []
                }
            },
            {
                "name": "workspace_diff",
                "description": "Get the git diff for all repos in a specific agent workspace, showing what the agent has changed relative to the upstream default branch.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "workspace": {
                            "type": "string",
                            "description": "Workspace name (pod name without 'devaipod-' prefix)"
                        }
                    },
                    "required": ["workspace"]
                }
            },
        ]
    })
}

async fn handle_tools_call(params: Option<Value>) -> Result<Value, Value> {
    let params = params.ok_or_else(|| json_rpc_error(-32602, "Missing params"))?;
    let name = params
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| json_rpc_error(-32602, "Missing tool name"))?
        .to_string();
    let arguments = params.get("arguments").cloned().unwrap_or(json!({}));

    // The advisor module's pod introspection functions use std::process::Command
    // (blocking I/O), so run them on the blocking threadpool.
    let result = tokio::task::spawn_blocking(move || match name.as_str() {
        "list_pods" => call_list_pods(),
        "pod_status" => call_pod_status(&arguments),
        "pod_logs" => call_pod_logs(&arguments),
        "propose_agent" => call_propose_agent(&arguments),
        "list_proposals" => call_list_proposals(&arguments),
        "list_workspaces" => call_list_workspaces(),
        "workspace_diff" => call_workspace_diff(&arguments),
        _ => Err(format!("Unknown tool: {}", name)),
    })
    .await
    .map_err(|e| json_rpc_error(-32603, &format!("Internal error: {}", e)))?;

    match result {
        Ok(text) => Ok(json!({
            "content": [{ "type": "text", "text": text }],
            "isError": false
        })),
        Err(e) => Ok(json!({
            "content": [{ "type": "text", "text": format!("Error: {}", e) }],
            "isError": true
        })),
    }
}

fn call_list_pods() -> Result<String, String> {
    let pods = advisor::list_pods().map_err(|e| e.to_string())?;
    serde_json::to_string_pretty(&pods).map_err(|e| e.to_string())
}

fn call_pod_status(args: &Value) -> Result<String, String> {
    let pod_name = args
        .get("pod_name")
        .and_then(|v| v.as_str())
        .ok_or("Missing pod_name argument")?;
    let pod_name = normalize_pod_name(pod_name);
    let status = advisor::pod_status(&pod_name).map_err(|e| e.to_string())?;
    serde_json::to_string_pretty(&status).map_err(|e| e.to_string())
}

fn call_pod_logs(args: &Value) -> Result<String, String> {
    let pod_name = args
        .get("pod_name")
        .and_then(|v| v.as_str())
        .ok_or("Missing pod_name argument")?;
    let pod_name = normalize_pod_name(pod_name);
    let lines = args.get("lines").and_then(|v| v.as_u64()).map(|v| v as u32);
    advisor::pod_logs(&pod_name, lines).map_err(|e| e.to_string())
}

fn call_propose_agent(args: &Value) -> Result<String, String> {
    use std::path::Path;

    let title = args
        .get("title")
        .and_then(|v| v.as_str())
        .ok_or("Missing title")?;
    let repo = args
        .get("repo")
        .and_then(|v| v.as_str())
        .ok_or("Missing repo")?;
    let task = args
        .get("task")
        .and_then(|v| v.as_str())
        .ok_or("Missing task")?;
    let rationale = args
        .get("rationale")
        .and_then(|v| v.as_str())
        .ok_or("Missing rationale")?;
    let priority = match args.get("priority").and_then(|v| v.as_str()) {
        Some("high") => advisor::Priority::High,
        Some("low") => advisor::Priority::Low,
        _ => advisor::Priority::Medium,
    };
    let source = args
        .get("source")
        .and_then(|v| v.as_str())
        .map(String::from);

    let mut store =
        advisor::DraftStore::load(Path::new(advisor::DRAFTS_PATH)).map_err(|e| e.to_string())?;
    let proposal = advisor::DraftProposal {
        id: String::new(), // set by add()
        title: title.to_string(),
        repo: repo.to_string(),
        task: task.to_string(),
        rationale: rationale.to_string(),
        priority,
        source,
        estimated_scope: args
            .get("estimated_scope")
            .and_then(|v| v.as_str())
            .map(String::from),
        status: advisor::ProposalStatus::default(),
        created_at: String::new(), // set by add()
    };
    let id = store.add(proposal);
    // Save is best-effort; the path may not be writable in the web container
    if let Err(e) = store.save(Path::new(advisor::DRAFTS_PATH)) {
        tracing::warn!("Could not persist draft store: {}", e);
    }

    Ok(format!("Created proposal '{}' with id {}", title, id))
}

fn call_list_proposals(args: &Value) -> Result<String, String> {
    use std::path::Path;

    let store =
        advisor::DraftStore::load(Path::new(advisor::DRAFTS_PATH)).map_err(|e| e.to_string())?;
    let status_filter = args
        .get("status")
        .and_then(|v| v.as_str())
        .map(|s| match s {
            "pending" => advisor::ProposalStatus::Pending,
            "approved" => advisor::ProposalStatus::Approved,
            "dismissed" => advisor::ProposalStatus::Dismissed,
            "expired" => advisor::ProposalStatus::Expired,
            _ => advisor::ProposalStatus::Pending,
        });

    let proposals = store.list(status_filter.as_ref());
    serde_json::to_string_pretty(&proposals).map_err(|e| e.to_string())
}

fn call_list_workspaces() -> Result<String, String> {
    let summaries = advisor::list_workspace_summaries().map_err(|e| e.to_string())?;
    serde_json::to_string_pretty(&summaries).map_err(|e| e.to_string())
}

fn call_workspace_diff(args: &Value) -> Result<String, String> {
    let workspace = args
        .get("workspace")
        .and_then(|v| v.as_str())
        .ok_or("Missing workspace argument")?;
    advisor::workspace_diff(workspace).map_err(|e| e.to_string())
}

/// Normalize pod name: ensure it has the "devaipod-" prefix.
fn normalize_pod_name(name: &str) -> String {
    if name.starts_with("devaipod-") {
        name.to_string()
    } else {
        format!("devaipod-{name}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::util::ServiceExt;

    /// Build a minimal router with just the MCP endpoint for testing.
    fn mcp_router() -> axum::Router {
        axum::Router::new().route("/mcp", axum::routing::post(handle_mcp))
    }

    #[tokio::test]
    async fn test_initialize() {
        let app = mcp_router();
        let body = serde_json::to_string(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {}
        }))
        .unwrap();

        let req = Request::builder()
            .method("POST")
            .uri("/mcp")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["result"]["serverInfo"]["name"], "devaipod");
        assert_eq!(json["id"], 1);
    }

    #[tokio::test]
    async fn test_notification_returns_202() {
        let app = mcp_router();
        let body = serde_json::to_string(&json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        }))
        .unwrap();

        let req = Request::builder()
            .method("POST")
            .uri("/mcp")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
    }

    #[tokio::test]
    async fn test_tools_list() {
        let app = mcp_router();
        let body = serde_json::to_string(&json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list"
        }))
        .unwrap();

        let req = Request::builder()
            .method("POST")
            .uri("/mcp")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        let tools = json["result"]["tools"].as_array().unwrap();
        assert!(tools.len() >= 7, "Expected at least 7 tools");

        let names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();
        assert!(names.contains(&"list_pods"));
        assert!(names.contains(&"pod_status"));
        assert!(names.contains(&"pod_logs"));
        assert!(names.contains(&"propose_agent"));
        assert!(names.contains(&"list_proposals"));
        assert!(names.contains(&"list_workspaces"));
        assert!(names.contains(&"workspace_diff"));
    }

    #[tokio::test]
    async fn test_unknown_method() {
        let app = mcp_router();
        let body = serde_json::to_string(&json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "nonexistent/method"
        }))
        .unwrap();

        let req = Request::builder()
            .method("POST")
            .uri("/mcp")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"]["code"], -32601);
    }

    #[tokio::test]
    async fn test_ping() {
        let app = mcp_router();
        let body = serde_json::to_string(&json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "ping"
        }))
        .unwrap();

        let req = Request::builder()
            .method("POST")
            .uri("/mcp")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["result"], json!({}));
    }

    /// Helper: send a tools/call request and return the parsed JSON response.
    async fn tools_call(tool_name: &str, arguments: Value) -> Value {
        let app = mcp_router();
        let body = serde_json::to_string(&json!({
            "jsonrpc": "2.0",
            "id": "test",
            "method": "tools/call",
            "params": { "name": tool_name, "arguments": arguments }
        }))
        .unwrap();

        let req = Request::builder()
            .method("POST")
            .uri("/mcp")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn test_tools_call_unknown_tool() {
        let json = tools_call("this_tool_does_not_exist", json!({})).await;
        assert_eq!(
            json["result"]["isError"], true,
            "unknown tool should set isError: true"
        );
        let text = json["result"]["content"][0]["text"].as_str().unwrap();
        assert!(
            text.contains("Unknown tool"),
            "expected 'Unknown tool' in error text, got: {text}"
        );
    }

    #[tokio::test]
    async fn test_tools_call_list_workspaces() {
        let json = tools_call("list_workspaces", json!({})).await;
        // Should succeed (isError false). The text content is a JSON array
        // (possibly empty if no workspaces exist).
        assert_eq!(
            json["result"]["isError"], false,
            "list_workspaces should succeed: {:?}",
            json["result"]
        );
        let text = json["result"]["content"][0]["text"].as_str().unwrap();
        let parsed: Vec<serde_json::Value> =
            serde_json::from_str(text).expect("list_workspaces output should be a JSON array");
        // It's fine if it's empty — the point is it returned valid JSON.
        assert!(parsed.len() < 10000, "sanity check on workspace count");
    }

    #[tokio::test]
    async fn test_tools_call_workspace_diff_nonexistent() {
        let json = tools_call(
            "workspace_diff",
            json!({ "workspace": "no-such-workspace-zzzzz" }),
        )
        .await;
        assert_eq!(
            json["result"]["isError"], true,
            "workspace_diff on missing workspace should fail"
        );
    }

    #[tokio::test]
    async fn test_tools_call_workspace_diff_path_traversal() {
        let json = tools_call("workspace_diff", json!({ "workspace": "../etc" })).await;
        assert_eq!(
            json["result"]["isError"], true,
            "path traversal should be rejected"
        );
        let text = json["result"]["content"][0]["text"].as_str().unwrap();
        assert!(
            text.contains("Invalid workspace name"),
            "expected path-traversal rejection, got: {text}"
        );
    }

    #[tokio::test]
    async fn test_tools_call_propose_agent() {
        let json = tools_call(
            "propose_agent",
            json!({
                "title": "Test proposal",
                "repo": "testorg/testrepo",
                "task": "Do the thing",
                "rationale": "Because tests",
                "priority": "low"
            }),
        )
        .await;
        // The call may fail to persist (DRAFTS_PATH not writable) but the
        // in-memory add succeeds and returns a well-formed response.
        // Either way, the response must be well-formed JSON-RPC.
        assert!(
            json.get("result").is_some(),
            "propose_agent should return a result (not a JSON-RPC error): {json:?}"
        );
        // If isError is false, the text should mention the created proposal.
        // If isError is true, it should still be a well-formed error message.
        let content = &json["result"]["content"];
        assert!(
            content.is_array() && !content.as_array().unwrap().is_empty(),
            "response should have content array"
        );
    }
}

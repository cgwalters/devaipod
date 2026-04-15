//! ACP (Agent Client Protocol) backend stub.
//!
//! This module implements [`AgentBackend`] for the ACP protocol over stdio.
//! It is currently a stub that compiles but does not perform real ACP
//! communication. Phase 2 will wire it up to spawn the agent process and
//! manage JSON-RPC sessions.
//!
//! ACP is an open standard (Apache-2.0, JSON-RPC 2.0 over stdio) that
//! standardizes communication between frontends and coding agents. See
//! <https://agentclientprotocol.com> for the specification.

use crate::agent::{
    AgentActivity, AgentBackend, AgentEnvConfig, AgentStartupConfig, AgentStatusSummary,
    MockServerConfig,
};

/// ACP backend over stdio.
///
/// When fully implemented (Phase 2), this backend will:
/// - Spawn the agent process with ACP over stdio
/// - Manage JSON-RPC sessions
/// - Track agent status from ACP event notifications
/// - Expose events over WebSocket for the frontend
///
/// Currently this is a compilable stub returning placeholder values.
#[derive(Debug, Clone)]
pub(crate) struct AcpBackend {
    /// The command to start the agent (e.g., `["opencode", "acp"]`).
    #[allow(dead_code)] // Will be used in Phase 2
    command: Vec<String>,
    /// Candidate binary names for availability checking in the startup script.
    /// These are the first element of each candidate profile's command.
    candidate_binaries: Vec<String>,
}

impl AcpBackend {
    /// Create a new ACP backend with the given agent command.
    ///
    /// For backwards compatibility, this sets candidate_binaries to a single
    /// element (the first element of command). Use `new_with_candidates` to
    /// provide a full list of binaries to check.
    #[allow(dead_code)] // Used in tests
    pub(crate) fn new(command: Vec<String>) -> Self {
        let candidate_binaries = command.first().map(|s| vec![s.clone()]).unwrap_or_default();
        Self {
            command,
            candidate_binaries,
        }
    }

    /// Create a new ACP backend with explicit candidate binaries.
    ///
    /// The `candidate_binaries` list is used by the startup script to verify
    /// at least one agent binary is available. This enables auto-detection
    /// when multiple agent profiles are configured.
    pub(crate) fn new_with_candidates(
        command: Vec<String>,
        candidate_binaries: Vec<String>,
    ) -> Self {
        Self {
            command,
            candidate_binaries,
        }
    }
}

#[async_trait::async_trait]
impl AgentBackend for AcpBackend {
    async fn query_status(&self, _password: &str, _port: u16) -> AgentStatusSummary {
        // Stub: ACP agents use stdio, not HTTP. Pod-api bypasses this trait
        // method and uses AcpClient directly to track session state via
        // JSON-RPC events. This stub exists to satisfy the AgentBackend trait
        // and is never called in production.
        //
        // If pod-api's health check needs ACP session state in the future,
        // the implementation should query the AcpClient (which is stored in
        // AppState, not accessible here).
        AgentStatusSummary {
            activity: AgentActivity::Unknown,
            status_line: Some("ACP backend not yet connected".to_string()),
            ..Default::default()
        }
    }

    fn startup_command(&self, agent_home: &str, state_path: &str) -> AgentStartupConfig {
        // ACP agents communicate via stdio, not HTTP. The agent process is
        // started on-demand by pod-api via `podman exec -i`, not as a
        // long-running server. The container just needs to stay alive so
        // pod-api can exec into it.
        //
        // Pre-flight check: verify at least one agent binary exists before
        // waiting for setup. This allows the control plane to detect missing
        // binaries and enter Degraded state with diagnostic information.
        let agent_binary_check = if !self.candidate_binaries.is_empty() {
            // Build a space-separated list of binaries for the error message
            let binaries_list = self
                .candidate_binaries
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(" ");

            // Build the shell loop to check each binary
            let mut checks = String::new();
            for binary in &self.candidate_binaries {
                checks.push_str(&format!(
                    "    if command -v {binary} >/dev/null 2>&1; then\n        FOUND_AGENT=\"{binary}\"\n        break\n    fi\n"
                ));
            }

            format!(
                r#"
# Pre-flight: verify at least one agent binary is available before waiting for setup.
# Skip in mock mode — the mock agent doesn't need the real binary.
if [ -z "${{DEVAIPOD_MOCK_AGENT}}" ]; then
    FOUND_AGENT=""
{checks}    if [ -z "$FOUND_AGENT" ]; then
        echo "devaipod-error: agent-binary-not-found: none of [{binaries_list}]" >&2
        exit 42
    fi
fi
"#
            )
        } else {
            String::new()
        };

        let startup_script = format!(
            r#"mkdir -p {home}/.config {home}/.local/share {home}/.local/bin {home}/.cache
{binary_check}
# Wait for devaipod to finish setup (dotfiles, task config).
while [ ! -f {state} ]; do
    sleep 0.1
done

# Mock ACP mode: when DEVAIPOD_MOCK_AGENT is set, install a Python script
# that responds to ACP JSON-RPC on stdio. Pod-api will exec into this
# container to start the mock agent.
if [ -n "${{DEVAIPOD_MOCK_AGENT}}" ]; then
    mkdir -p {home}/.local/bin
    cat > {home}/.local/bin/mock-acp-agent << 'MOCK_SCRIPT'
#!/usr/bin/env python3
"""Minimal ACP mock agent for integration testing."""
import sys, json

def respond(id, result):
    msg = json.dumps({{"jsonrpc": "2.0", "id": id, "result": result}})
    sys.stdout.write(msg + "\n")
    sys.stdout.flush()

def notify(method, params):
    msg = json.dumps({{"jsonrpc": "2.0", "method": method, "params": params}})
    sys.stdout.write(msg + "\n")
    sys.stdout.flush()

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        req = json.loads(line)
    except json.JSONDecodeError:
        continue
    method = req.get("method", "")
    rid = req.get("id")
    if method == "initialize":
        respond(rid, {{
            "protocolVersion": 1,
            "agentCapabilities": {{"loadSession": True}},
            "agentInfo": {{"name": "MockAgent", "version": "1.0.0"}}
        }})
    elif method == "session/new":
        sid = "mock-session-001"
        respond(rid, {{"sessionId": sid, "modes": {{}}}})
    elif method == "session/list":
        respond(rid, {{"sessions": [{{"sessionId": "mock-session-001", "title": "Mock session"}}]}})
    elif method == "session/load":
        notify("session/update", {{
            "sessionId": req.get("params", {{}}).get("sessionId", ""),
            "update": {{"sessionUpdate": "agent_message_chunk", "content": {{"type": "text", "text": "Mock session loaded."}}}}
        }})
        respond(rid, {{}})
    elif method == "session/prompt":
        sid = req.get("params", {{}}).get("sessionId", "")
        notify("session/update", {{
            "sessionId": sid,
            "update": {{"sessionUpdate": "agent_message_chunk", "content": {{"type": "text", "text": "Mock response."}}}}
        }})
        respond(rid, {{"stopReason": "end_turn"}})
    elif method == "session/cancel":
        if rid:
            respond(rid, {{}})
    elif method == "initialized":
        pass  # notification, no response needed
    else:
        if rid:
            respond(rid, {{}})
MOCK_SCRIPT
    chmod +x {home}/.local/bin/mock-acp-agent
fi

# Keep the container alive. Pod-api will start the ACP session on-demand
# via `podman exec -i <agent-container> <agent-command>`.
while true; do
    sleep 3600
done"#,
            home = agent_home,
            state = state_path,
            binary_check = agent_binary_check,
        );

        AgentStartupConfig {
            startup_script,
            // ACP uses stdio, not a network port.
            listen_port: None,
        }
    }

    fn container_env(&self, config: &AgentEnvConfig) -> Vec<(String, String)> {
        // ACP backends configure tool permissions through the ACP protocol
        // (session/request_permission), not through environment variables.
        // However, agents still need MCP server config so they can access
        // MCP tools like service-gator.
        //
        // Generate OPENCODE_CONFIG_CONTENT from the MCP servers list.
        // This is the same format used by the old OpenCode HTTP backend.
        let mut env = vec![];

        if !config.mcp_servers.is_empty() {
            let mut mcp_servers_map = serde_json::Map::new();

            // mcp_servers is Vec<(String, serde_json::Value)>
            // where the tuple is (name, server_config_json)
            for (name, server_json) in &config.mcp_servers {
                mcp_servers_map.insert(name.clone(), server_json.clone());
            }

            let mcp_config = serde_json::json!({
                "mcp": mcp_servers_map
            });

            env.push((
                "OPENCODE_CONFIG_CONTENT".to_string(),
                mcp_config.to_string(),
            ));
        }

        env
    }

    fn mock_config(&self, port: u16) -> MockServerConfig {
        MockServerConfig {
            port,
            // ACP uses stdio, not HTTP. The mock will be a stdio-based
            // JSON-RPC server in Phase 2.
            is_http: false,
        }
    }

    fn name(&self) -> &str {
        "acp"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_acp_backend_name() {
        let backend = AcpBackend::new(vec!["opencode".to_string(), "acp".to_string()]);
        assert_eq!(backend.name(), "acp");
    }

    #[test]
    fn test_acp_backend_startup_command() {
        let backend = AcpBackend::new(vec!["opencode".to_string(), "acp".to_string()]);
        let config = backend.startup_command("/home/devenv", "/var/lib/state.json");
        assert!(config.listen_port.is_none(), "ACP uses stdio, not a port");
        assert!(
            config.startup_script.contains("while true"),
            "startup script should keep container alive with infinite loop"
        );
        // The startup script now includes "command -v opencode" for the pre-flight
        // check, but should not run "opencode serve" or "exec opencode".
        assert!(
            config.startup_script.contains("command -v opencode"),
            "startup script should check for opencode binary"
        );
        assert!(
            !config.startup_script.contains("exec opencode"),
            "startup script should not exec opencode (run via podman exec instead)"
        );
    }

    #[test]
    fn test_acp_backend_startup_command_default() {
        let backend = AcpBackend::new(vec![]);
        let config = backend.startup_command("/home/devenv", "/var/lib/state.json");
        assert!(
            config.startup_script.contains("sleep 3600"),
            "startup script should keep container alive"
        );
        assert!(
            !config.startup_script.contains("opencode"),
            "agent command should not be in startup script (run via podman exec instead)"
        );
        assert!(
            !config.startup_script.contains("command -v"),
            "empty command vec should not generate binary check"
        );
    }

    #[test]
    fn test_acp_backend_startup_command_with_binary_check() {
        let backend = AcpBackend::new(vec!["opencode".to_string(), "acp".to_string()]);
        let config = backend.startup_command("/home/devenv", "/var/lib/state.json");
        assert!(
            config.startup_script.contains("command -v opencode"),
            "should check for opencode binary"
        );
        assert!(
            config
                .startup_script
                .contains("devaipod-error: agent-binary-not-found: none of [opencode]"),
            "should print diagnostic message on missing binary"
        );
        assert!(
            config.startup_script.contains("exit 42"),
            "should exit with code 42 on missing binary"
        );
    }

    #[test]
    fn test_acp_backend_startup_command_multi_binary_check() {
        let backend = AcpBackend::new_with_candidates(
            vec!["opencode".to_string(), "acp".to_string()],
            vec!["goose".to_string(), "opencode".to_string()],
        );
        let config = backend.startup_command("/home/devenv", "/var/lib/state.json");
        // Should check for both goose and opencode
        assert!(
            config.startup_script.contains("command -v goose"),
            "should check for goose binary"
        );
        assert!(
            config.startup_script.contains("command -v opencode"),
            "should check for opencode binary"
        );
        assert!(
            config
                .startup_script
                .contains("devaipod-error: agent-binary-not-found: none of [goose opencode]"),
            "should list all candidate binaries in error message"
        );
        assert!(
            config.startup_script.contains("FOUND_AGENT="),
            "should track which binary was found"
        );
    }

    #[test]
    fn test_acp_backend_container_env_empty_when_no_mcp_servers() {
        let backend = AcpBackend::new(vec!["opencode".to_string(), "acp".to_string()]);
        let env_config = AgentEnvConfig {
            agent_home: "/home/devenv".to_string(),
            enable_gator: true,
            gator_port: 8765,
            enable_orchestration: false,
            worker_port: 4098,
            mcp_servers: vec![],
        };
        let env = backend.container_env(&env_config);
        assert!(
            env.is_empty(),
            "No MCP servers means no OPENCODE_CONFIG_CONTENT"
        );
    }

    #[test]
    fn test_acp_backend_container_env_with_mcp_servers() {
        let backend = AcpBackend::new(vec!["opencode".to_string(), "acp".to_string()]);
        let env_config = AgentEnvConfig {
            agent_home: "/home/devenv".to_string(),
            enable_gator: true,
            gator_port: 8765,
            enable_orchestration: false,
            worker_port: 4098,
            mcp_servers: vec![(
                "service-gator".to_string(),
                serde_json::json!({
                    "type": "remote",
                    "url": "http://localhost:8765/mcp",
                    "enabled": true
                }),
            )],
        };
        let env = backend.container_env(&env_config);
        assert_eq!(env.len(), 1, "Should have OPENCODE_CONFIG_CONTENT");

        let (key, value) = &env[0];
        assert_eq!(key, "OPENCODE_CONFIG_CONTENT");
        assert!(
            value.contains("service-gator"),
            "Config should reference service-gator"
        );
        assert!(
            value.contains("http://localhost:8765/mcp"),
            "Config should have gator URL"
        );

        // Verify it's valid JSON
        let parsed: serde_json::Value = serde_json::from_str(value).expect("should be valid JSON");
        assert!(parsed.get("mcp").is_some(), "Should have 'mcp' field");
    }

    #[test]
    fn test_acp_backend_mock_config() {
        let backend = AcpBackend::new(vec![]);
        let config = backend.mock_config(4096);
        assert_eq!(config.port, 4096);
        assert!(!config.is_http, "ACP mock should use stdio, not HTTP");
    }

    #[tokio::test]
    async fn test_acp_backend_query_status_returns_unknown() {
        let backend = AcpBackend::new(vec![]);
        let status = backend.query_status("", 0).await;
        assert_eq!(status.activity, AgentActivity::Unknown);
        assert!(status.status_line.is_some());
    }

    #[test]
    fn test_acp_backend_is_object_safe() {
        let _: Box<dyn AgentBackend> = Box::new(AcpBackend::new(vec![]));
    }
}

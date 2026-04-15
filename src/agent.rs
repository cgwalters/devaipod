//! Agent backend trait and shared types.
//!
//! Abstracts what devaipod needs from an agent backend.
//!
//! Current implementation:
//! - ACP (Agent Client Protocol) over stdio (`agent_acp.rs`)
//!
//! The trait is object-safe so it can be used as `Box<dyn AgentBackend>`.
//!
//! These types are defined now (Phase 1) but will be wired into pod_api
//! and pod.rs in Phase 2.

use serde::Serialize;

/// High-level activity state of the agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) enum AgentActivity {
    /// Agent is actively processing a request or running tools.
    #[allow(dead_code)] // Used by OpenCode backend, kept for future use
    Working,
    /// Agent is idle, waiting for input.
    Idle,
    /// Agent is stopped or not running.
    #[allow(dead_code)] // Used by ACP backend in Phase 3
    Stopped,
    /// Agent state cannot be determined.
    Unknown,
}

impl AgentActivity {
    /// Convert to the string representation used by the control plane.
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            AgentActivity::Working => "Working",
            AgentActivity::Idle => "Idle",
            AgentActivity::Stopped => "Stopped",
            AgentActivity::Unknown => "Unknown",
        }
    }
}

impl std::fmt::Display for AgentActivity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Structured status summary of the agent.
///
/// Returned by [`AgentBackend::query_status`]. Contains everything the
/// control plane needs to display agent state without knowing which
/// backend is in use.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct AgentStatusSummary {
    /// High-level activity: Working, Idle, Stopped, Unknown.
    pub(crate) activity: AgentActivity,
    /// One-line description of what the agent is doing.
    pub(crate) status_line: Option<String>,
    /// Currently executing tool (if any).
    pub(crate) current_tool: Option<String>,
    /// Last few lines of agent output for quick preview.
    pub(crate) recent_output: Vec<String>,
    /// Epoch millis of the most recent message.
    pub(crate) last_message_ts: Option<i64>,
    /// Total number of sessions in this pod.
    pub(crate) session_count: usize,
}

impl Default for AgentStatusSummary {
    fn default() -> Self {
        Self {
            activity: AgentActivity::Unknown,
            status_line: None,
            current_tool: None,
            recent_output: vec![],
            last_message_ts: None,
            session_count: 0,
        }
    }
}

/// Configuration needed to generate agent container environment variables.
///
/// Passed to [`AgentBackend::container_env`] so the backend can produce
/// agent-specific env vars without reaching into global config itself.
#[derive(Debug, Clone)]
#[allow(dead_code)] // Fields are set by pod.rs, read by backend implementations
pub(crate) struct AgentEnvConfig {
    /// Home directory inside the agent container.
    pub(crate) agent_home: String,
    /// Whether service-gator is enabled.
    pub(crate) enable_gator: bool,
    /// Port of the service-gator MCP server (if enabled).
    pub(crate) gator_port: u16,
    /// Whether orchestration mode is enabled.
    pub(crate) enable_orchestration: bool,
    /// Port of the worker's server (if orchestration is enabled).
    pub(crate) worker_port: u16,
    /// Additional MCP servers from config as `(name, json_value)` pairs.
    pub(crate) mcp_servers: Vec<(String, serde_json::Value)>,
}

/// Configuration for starting the agent inside a container.
///
/// Returned by [`AgentBackend::startup_command`]. The container
/// orchestration code uses this to build the container entrypoint.
#[derive(Debug, Clone)]
pub(crate) struct AgentStartupConfig {
    /// Shell script to run as the container entrypoint.
    ///
    /// Executed via `/bin/sh -c <script>`. The script should `exec` the
    /// final process so it becomes PID 1 and receives signals correctly.
    pub(crate) startup_script: String,
    /// The port the agent listens on (if any).
    ///
    /// For HTTP backends (opencode-legacy) this is the HTTP port; for ACP
    /// backends this is `None` (communication is via stdio). Currently
    /// only used by tests to verify backend behavior.
    #[allow(dead_code)]
    pub(crate) listen_port: Option<u16>,
}

/// Mock server configuration for integration testing.
///
/// Returned by [`AgentBackend::mock_config`]. Contains the routes and
/// port configuration needed to run a mock agent server.
#[derive(Debug, Clone)]
pub(crate) struct MockServerConfig {
    /// Port the mock should listen on.
    #[allow(dead_code)] // Used by integration tests
    pub(crate) port: u16,
    /// Whether the mock uses HTTP (true) or stdio (false).
    #[allow(dead_code)] // Used by integration tests
    pub(crate) is_http: bool,
}

/// Trait abstracting what devaipod needs from an agent backend.
///
/// Current implementation:
/// - ACP (Agent Client Protocol) over stdio — [`crate::agent_acp::AcpBackend`]
///
/// The trait is object-safe: `Box<dyn AgentBackend>` compiles.
#[async_trait::async_trait]
pub(crate) trait AgentBackend: Send + Sync + std::fmt::Debug {
    /// Query the agent for a status summary.
    ///
    /// For HTTP backends, this makes HTTP requests to the agent server.
    /// For ACP backends, this reads the latest state from the ACP session.
    ///
    /// The `password` and `port` parameters are the credentials/port for
    /// HTTP-based backends. ACP backends ignore them.
    ///
    /// Note: This method is no longer used by pod_api.rs (which uses AcpClient
    /// directly). It remains for pod.rs container orchestration.
    #[allow(dead_code)] // Used by pod.rs for container health checks
    async fn query_status(&self, password: &str, port: u16) -> AgentStatusSummary;

    /// Return the container startup script and listen port.
    ///
    /// The returned [`AgentStartupConfig`] is used to build the container
    /// entrypoint command. The `agent_home` and `state_path` parameters
    /// provide paths that the startup script needs.
    fn startup_command(&self, agent_home: &str, state_path: &str) -> AgentStartupConfig;

    /// Return agent-specific environment variables for the container.
    ///
    /// These are merged with the common env vars generated by the pod
    /// creation logic.
    fn container_env(&self, config: &AgentEnvConfig) -> Vec<(String, String)>;

    /// Return the configuration for running a mock agent server.
    ///
    /// Used in integration tests to provide a test double.
    #[allow(dead_code)] // Will be used by integration test harness
    fn mock_config(&self, port: u16) -> MockServerConfig;

    /// Returns the agent's display name (e.g. "opencode", "acp").
    #[allow(dead_code)] // Used by logging and display
    fn name(&self) -> &str;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify the trait is object-safe by constructing a `Box<dyn AgentBackend>`.
    #[test]
    fn trait_is_object_safe() {
        fn _assert_object_safe(_: Box<dyn AgentBackend>) {}
        // This test passes if it compiles.
    }

    #[test]
    fn agent_activity_display() {
        assert_eq!(AgentActivity::Working.as_str(), "Working");
        assert_eq!(AgentActivity::Idle.as_str(), "Idle");
        assert_eq!(AgentActivity::Stopped.as_str(), "Stopped");
        assert_eq!(AgentActivity::Unknown.as_str(), "Unknown");
        assert_eq!(format!("{}", AgentActivity::Working), "Working");
    }

    #[test]
    fn agent_status_summary_default() {
        let summary = AgentStatusSummary::default();
        assert_eq!(summary.activity, AgentActivity::Unknown);
        assert!(summary.status_line.is_none());
        assert!(summary.current_tool.is_none());
        assert!(summary.recent_output.is_empty());
        assert!(summary.last_message_ts.is_none());
        assert_eq!(summary.session_count, 0);
    }
}

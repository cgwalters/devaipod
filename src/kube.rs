//! Kubernetes backend for devaipod
//!
//! Provides client initialization and cluster connectivity for spawning
//! workspace pods in a Kubernetes cluster. The kubeconfig can come from:
//!
//! 1. A podman secret (highest priority) — for the hybrid model where the
//!    controlplane runs locally but manages remote cluster workspaces
//! 2. A file path specified in config
//! 3. In-cluster ServiceAccount detection (when devaipod itself runs in k8s)
//! 4. Default kubeconfig (~/.kube/config)

use color_eyre::eyre::{Context, Result};

use crate::config::KubernetesConfig;

/// An initialized Kubernetes client with its target namespace.
///
/// Created via [`connect`] when the `[kubernetes]` config section is enabled.
/// The client is cheaply cloneable (internally Arc'd) and safe to share
/// across async tasks.
#[derive(Clone)]
pub struct KubeClient {
    /// The authenticated Kubernetes API client.
    pub client: kube::Client,
    /// Target namespace for workspace pods.
    pub namespace: String,
    /// Server version string, captured at connect time for diagnostics.
    pub server_version: String,
}

impl std::fmt::Debug for KubeClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KubeClient")
            .field("namespace", &self.namespace)
            .field("server_version", &self.server_version)
            .finish_non_exhaustive()
    }
}

/// Attempt to connect to a Kubernetes cluster using the provided configuration.
///
/// Tries kubeconfig sources in priority order:
/// 1. `kubeconfig-secret` (podman secret containing kubeconfig YAML)
/// 2. `kubeconfig-path` (explicit file path)
/// 3. Default detection (in-cluster or ~/.kube/config)
pub async fn connect(config: &KubernetesConfig) -> Result<KubeClient> {
    // kube-rs uses rustls for TLS; ensure the process-level crypto provider
    // is installed. Ignore AlreadyInstalled errors (russh may have set it).
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let client = if let Some(secret_name) = &config.kubeconfig_secret {
        client_from_podman_secret(secret_name).await?
    } else if let Some(path) = &config.kubeconfig_path {
        client_from_file(path).await?
    } else {
        client_from_default().await?
    };

    // Verify connectivity by fetching server version
    let version = client
        .apiserver_version()
        .await
        .context("failed to contact Kubernetes API server")?;
    let server_version = format!("{}.{}", version.major, version.minor);

    tracing::info!(
        server_version = %server_version,
        namespace = %config.namespace(),
        "connected to Kubernetes cluster"
    );

    Ok(KubeClient {
        client,
        namespace: config.namespace().to_string(),
        server_version,
    })
}

/// Build a [`kube::Client`] from a podman secret containing kubeconfig YAML.
async fn client_from_podman_secret(secret_name: &str) -> Result<kube::Client> {
    tracing::debug!(secret = %secret_name, "loading kubeconfig from podman secret");

    let yaml = fetch_podman_secret_value(secret_name)
        .context("failed to read kubeconfig from podman secret")?;

    client_from_kubeconfig_yaml(&yaml).await
}

/// Build a [`kube::Client`] from a kubeconfig file path.
async fn client_from_file(path: &str) -> Result<kube::Client> {
    tracing::debug!(path = %path, "loading kubeconfig from file");

    let yaml = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read kubeconfig from {path}"))?;

    client_from_kubeconfig_yaml(&yaml).await
}

/// Build a [`kube::Client`] using default detection (in-cluster or ~/.kube/config).
async fn client_from_default() -> Result<kube::Client> {
    tracing::debug!("using default kubeconfig detection (in-cluster or ~/.kube/config)");

    kube::Client::try_default()
        .await
        .context("failed to create Kubernetes client from default config")
}

/// Parse kubeconfig YAML text and build a client from it.
async fn client_from_kubeconfig_yaml(yaml: &str) -> Result<kube::Client> {
    let kubeconfig =
        kube::config::Kubeconfig::from_yaml(yaml).context("failed to parse kubeconfig YAML")?;

    let config = kube::Config::from_custom_kubeconfig(
        kubeconfig,
        &kube::config::KubeConfigOptions::default(),
    )
    .await
    .context("failed to resolve kubeconfig (check cluster URL and credentials)")?;

    kube::Client::try_from(config).context("failed to build Kubernetes HTTP client")
}

/// Read a secret value from the podman secrets store.
///
/// Shells out to `podman secret inspect --showsecret` and extracts the
/// SecretData field from the JSON response.
fn fetch_podman_secret_value(secret_name: &str) -> Result<String> {
    let output = std::process::Command::new("podman")
        .args(["secret", "inspect", secret_name, "--showsecret"])
        .output()
        .with_context(|| format!("failed to run podman secret inspect for '{secret_name}'"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(color_eyre::eyre::eyre!(
            "podman secret '{secret_name}' not found: {}",
            stderr.trim()
        ));
    }

    parse_podman_secret_json(&output.stdout, secret_name)
}

/// Extract the SecretData field from `podman secret inspect --showsecret` JSON output.
///
/// The output format is an array with a single object containing a `SecretData` string.
fn parse_podman_secret_json(output: &[u8], secret_name: &str) -> Result<String> {
    let json: serde_json::Value = serde_json::from_slice(output)
        .with_context(|| format!("failed to parse podman output for secret '{secret_name}'"))?;

    json.as_array()
        .and_then(|arr| arr.first())
        .and_then(|obj| obj.get("SecretData"))
        .and_then(|s| s.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| {
            color_eyre::eyre::eyre!(
                "could not extract SecretData for '{secret_name}' \
                 (unexpected JSON structure)"
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kubernetes_config_defaults() {
        let config = KubernetesConfig::default();
        assert!(!config.is_enabled());
        assert_eq!(config.namespace(), "devaipod");
        assert!(config.kubeconfig_secret.is_none());
        assert!(config.kubeconfig_path.is_none());
    }

    #[test]
    fn test_kubernetes_config_from_toml() {
        let toml = r#"
            enabled = true
            namespace = "my-namespace"
            kubeconfig-secret = "my-kubeconfig"
        "#;
        let config: KubernetesConfig = toml::from_str(toml).unwrap();
        assert!(config.is_enabled());
        assert_eq!(config.namespace(), "my-namespace");
        assert_eq!(config.kubeconfig_secret.as_deref(), Some("my-kubeconfig"));
    }

    #[test]
    fn test_kubernetes_config_minimal_toml() {
        let toml = "enabled = true\n";
        let config: KubernetesConfig = toml::from_str(toml).unwrap();
        assert!(config.is_enabled());
        assert_eq!(config.namespace(), "devaipod");
    }

    #[test]
    fn test_full_config_with_kubernetes() {
        let toml = r#"
            [kubernetes]
            enabled = true
            namespace = "test-ns"
            kubeconfig-path = "/tmp/kubeconfig"
        "#;
        let config: crate::config::Config = toml::from_str(toml).unwrap();
        assert!(config.kubernetes.is_enabled());
        assert_eq!(config.kubernetes.namespace(), "test-ns");
        assert_eq!(
            config.kubernetes.kubeconfig_path.as_deref(),
            Some("/tmp/kubeconfig")
        );
    }

    #[test]
    fn test_parse_podman_secret_json() {
        // Real `podman secret inspect --showsecret` output format
        let json = br#"[{"ID":"abc123","CreatedAt":"2026-01-01T00:00:00Z","UpdatedAt":"2026-01-01T00:00:00Z","Spec":{"Name":"kubeconfig","Driver":{}},"SecretData":"apiVersion: v1\nclusters: []\n"}]"#;
        let result = parse_podman_secret_json(json, "kubeconfig").unwrap();
        assert!(result.starts_with("apiVersion: v1"));
    }

    #[test]
    fn test_parse_podman_secret_json_empty_array() {
        let json = b"[]";
        let result = parse_podman_secret_json(json, "missing");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("could not extract SecretData"));
    }

    #[test]
    fn test_parse_podman_secret_json_invalid() {
        let json = b"not json";
        let result = parse_podman_secret_json(json, "bad");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("failed to parse"));
    }
}

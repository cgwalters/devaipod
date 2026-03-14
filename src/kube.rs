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

    let namespace = config.namespace().to_string();

    // Ensure the target namespace exists (create if absent).
    ensure_namespace(&client, &namespace).await?;

    tracing::info!(
        server_version = %server_version,
        namespace = %namespace,
        "connected to Kubernetes cluster"
    );

    Ok(KubeClient {
        client,
        namespace,
        server_version,
    })
}

/// Ensure a namespace exists, creating it if absent.
///
/// This is idempotent: if the namespace already exists, it's a no-op.
async fn ensure_namespace(client: &kube::Client, name: &str) -> Result<()> {
    use k8s_openapi::api::core::v1::Namespace;
    use kube::api::{ObjectMeta, PostParams};

    let ns_api: kube::Api<Namespace> = kube::Api::all(client.clone());

    // Check if it already exists before trying to create
    match ns_api.get(name).await {
        Ok(_) => {
            tracing::debug!(namespace = %name, "namespace already exists");
            return Ok(());
        }
        Err(kube::Error::Api(e)) if e.code == 404 => {
            // Doesn't exist, create it below
        }
        Err(e) => {
            return Err(e).context(format!("failed to check namespace '{name}'"));
        }
    }

    let ns = Namespace {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            labels: Some(std::collections::BTreeMap::from([(
                "io.devaipod/managed".to_string(),
                "true".to_string(),
            )])),
            ..Default::default()
        },
        ..Default::default()
    };

    match ns_api.create(&PostParams::default(), &ns).await {
        Ok(_) => {
            tracing::info!(namespace = %name, "created namespace");
            Ok(())
        }
        // Race: another process created it between our get and create
        Err(kube::Error::Api(e)) if e.code == 409 => {
            tracing::debug!(namespace = %name, "namespace created concurrently");
            Ok(())
        }
        Err(e) => Err(e).context(format!("failed to create namespace '{name}'")),
    }
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

// ---------------------------------------------------------------------------
// KubeBackend — ContainerBackend implementation for Kubernetes
// ---------------------------------------------------------------------------

/// Kubernetes implementation of [`ContainerBackend`].
///
/// Creates workspace pods as native Kubernetes Pods in the configured
/// namespace. Init containers, volumes, env vars, and secrets are all
/// expressed in the Pod manifest. The backend assumes it runs in the same
/// cluster (in-cluster ServiceAccount or matching kubeconfig).
#[allow(dead_code)]
pub struct KubeBackend {
    client: KubeClient,
}

#[allow(dead_code)]
impl KubeBackend {
    /// Create a new KubeBackend from an established client connection.
    pub fn new(client: KubeClient) -> Self {
        Self { client }
    }

    /// Translate a [`WorkspacePodSpec`] into a Kubernetes Pod manifest.
    fn build_pod_manifest(
        &self,
        spec: &crate::backend::WorkspacePodSpec,
    ) -> k8s_openapi::api::core::v1::Pod {
        build_pod_manifest_for_namespace(spec, &self.client.namespace)
    }
}

/// Build a Pod manifest from a [`WorkspacePodSpec`], targeting the given namespace.
///
/// Extracted as a standalone function so unit tests can exercise manifest
/// generation without constructing a real [`KubeClient`].
///
/// Maps our backend-agnostic spec types to native k8s objects including
/// security contexts, healthcheck probes, and secret references.
fn build_pod_manifest_for_namespace(
    spec: &crate::backend::WorkspacePodSpec,
    namespace: &str,
) -> k8s_openapi::api::core::v1::Pod {
    use k8s_openapi::api::core::v1::{
        Container, EmptyDirVolumeSource, EnvVar, PersistentVolumeClaimVolumeSource, Pod, PodSpec,
        Volume, VolumeMount,
    };
    use kube::api::ObjectMeta;

    let labels: std::collections::BTreeMap<String, String> = spec.labels.clone();
    let annotations: std::collections::BTreeMap<String, String> = spec.annotations.clone();

    // Build volumes
    let volumes: Vec<Volume> = spec
        .volumes
        .iter()
        .map(|v| match &v.volume_type {
            crate::backend::VolumeType::Persistent => Volume {
                name: v.name.clone(),
                persistent_volume_claim: Some(PersistentVolumeClaimVolumeSource {
                    claim_name: v.name.clone(),
                    ..Default::default()
                }),
                ..Default::default()
            },
            crate::backend::VolumeType::Ephemeral => Volume {
                name: v.name.clone(),
                empty_dir: Some(EmptyDirVolumeSource::default()),
                ..Default::default()
            },
        })
        .collect();

    // Build a lookup of secret refs by name for env var injection
    let secret_map: std::collections::HashMap<&str, &crate::backend::SecretRef> =
        spec.secrets.iter().map(|s| (s.name.as_str(), s)).collect();

    // Translate container specs
    let containers: Vec<Container> = spec
        .containers
        .iter()
        .map(|c| translate_container_spec(c, &secret_map))
        .collect();

    // Translate init containers
    let init_containers: Option<Vec<Container>> = if spec.init_containers.is_empty() {
        None
    } else {
        Some(
            spec.init_containers
                .iter()
                .map(|ic| {
                    let env: Vec<EnvVar> = ic
                        .env
                        .iter()
                        .map(|(k, v)| EnvVar {
                            name: k.clone(),
                            value: Some(v.clone()),
                            ..Default::default()
                        })
                        .collect();

                    let volume_mounts: Vec<VolumeMount> = ic
                        .volume_mounts
                        .iter()
                        .map(|vm| VolumeMount {
                            name: vm.volume.clone(),
                            mount_path: vm.mount_path.clone(),
                            read_only: Some(vm.read_only),
                            ..Default::default()
                        })
                        .collect();

                    // Init containers that need root get a security context
                    let security_context = ic.user.as_deref().and_then(|u| {
                        u.parse::<i64>().ok().map(|uid| {
                            k8s_openapi::api::core::v1::SecurityContext {
                                run_as_user: Some(uid),
                                ..Default::default()
                            }
                        })
                    });

                    Container {
                        name: ic.name.clone(),
                        image: Some(ic.image.clone()),
                        image_pull_policy: Some("IfNotPresent".to_string()),
                        command: Some(ic.command.clone()),
                        env: Some(env),
                        volume_mounts: Some(volume_mounts),
                        security_context,
                        ..Default::default()
                    }
                })
                .collect(),
        )
    };

    Pod {
        metadata: ObjectMeta {
            name: Some(spec.name.clone()),
            namespace: Some(namespace.to_string()),
            labels: Some(labels),
            annotations: Some(annotations),
            ..Default::default()
        },
        spec: Some(PodSpec {
            init_containers,
            containers,
            volumes: Some(volumes),
            restart_policy: Some("Never".to_string()),
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// Translate a single [`ContainerSpec`] into a k8s Container, including
/// security context, healthcheck probe, and secret env var references.
fn translate_container_spec(
    c: &crate::backend::ContainerSpec,
    secret_map: &std::collections::HashMap<&str, &crate::backend::SecretRef>,
) -> k8s_openapi::api::core::v1::Container {
    use k8s_openapi::api::core::v1::{
        Capabilities, Container, ContainerPort, EnvVar, EnvVarSource, ExecAction, Probe,
        SecretKeySelector, VolumeMount,
    };

    // Plain env vars
    let mut env: Vec<EnvVar> = c
        .env
        .iter()
        .map(|(k, v)| EnvVar {
            name: k.clone(),
            value: Some(v.clone()),
            ..Default::default()
        })
        .collect();

    // Secret-backed env vars: look up each secret ref and translate to
    // k8s secretKeyRef (the k8s Secret must exist in the namespace).
    for secret_name in &c.secret_refs {
        if let Some(secret_ref) = secret_map.get(secret_name.as_str()) {
            match &secret_ref.injection {
                crate::backend::SecretInjection::EnvVar { var_name, key } => {
                    env.push(EnvVar {
                        name: var_name.clone(),
                        value_from: Some(EnvVarSource {
                            secret_key_ref: Some(SecretKeySelector {
                                name: secret_ref.name.clone(),
                                key: key.clone(),
                                optional: Some(true),
                            }),
                            ..Default::default()
                        }),
                        ..Default::default()
                    });
                }
                crate::backend::SecretInjection::File { .. } => {
                    // File-based secrets would need a volume mount; for now we
                    // log a warning since this path isn't used yet.
                    tracing::warn!(
                        secret = %secret_ref.name,
                        "file-based secret injection not yet supported in k8s backend"
                    );
                }
            }
        }
    }

    let volume_mounts: Vec<VolumeMount> = c
        .volume_mounts
        .iter()
        .map(|vm| VolumeMount {
            name: vm.volume.clone(),
            mount_path: vm.mount_path.clone(),
            read_only: Some(vm.read_only),
            ..Default::default()
        })
        .collect();

    let ports: Option<Vec<ContainerPort>> = if c.ports.is_empty() {
        None
    } else {
        Some(
            c.ports
                .iter()
                .map(|p| ContainerPort {
                    container_port: p.container_port as i32,
                    name: p.name.clone(),
                    ..Default::default()
                })
                .collect(),
        )
    };

    // TODO: ContainerSpec.user and SecurityContext.security_opts are not yet
    // translated. user would map to runAsUser in the k8s SecurityContext;
    // security_opts (SELinux/AppArmor) would map to seLinuxOptions/appArmorProfile.
    // Currently unused in spec construction, so deferring.

    // Translate security context
    let security_context = {
        let sec = &c.security;
        let has_security =
            sec.privileged || sec.drop_all_caps || !sec.cap_add.is_empty() || sec.no_new_privileges;

        if has_security {
            let capabilities = if sec.drop_all_caps || !sec.cap_add.is_empty() {
                Some(Capabilities {
                    drop: if sec.drop_all_caps {
                        Some(vec!["ALL".to_string()])
                    } else {
                        None
                    },
                    add: if sec.cap_add.is_empty() {
                        None
                    } else {
                        Some(sec.cap_add.clone())
                    },
                })
            } else {
                None
            };

            Some(k8s_openapi::api::core::v1::SecurityContext {
                privileged: if sec.privileged { Some(true) } else { None },
                capabilities,
                allow_privilege_escalation: if sec.no_new_privileges {
                    Some(false)
                } else {
                    None
                },
                ..Default::default()
            })
        } else {
            None
        }
    };

    // Translate healthcheck to liveness probe
    let liveness_probe = c.healthcheck.as_ref().map(|hc| Probe {
        exec: Some(ExecAction {
            command: Some(hc.command.clone()),
        }),
        period_seconds: Some(hc.interval_secs as i32),
        failure_threshold: Some(hc.retries as i32),
        initial_delay_seconds: Some(hc.initial_delay_secs as i32),
        ..Default::default()
    });

    Container {
        name: c.name.clone(),
        image: Some(c.image.clone()),
        image_pull_policy: Some("IfNotPresent".to_string()),
        command: c.command.clone(),
        env: Some(env),
        volume_mounts: Some(volume_mounts),
        working_dir: c.workdir.clone(),
        ports,
        security_context,
        liveness_probe,
        ..Default::default()
    }
}

#[async_trait::async_trait]
impl crate::backend::ContainerBackend for KubeBackend {
    async fn create_workspace_pod(
        &self,
        spec: &crate::backend::WorkspacePodSpec,
    ) -> Result<String> {
        use kube::api::PostParams;

        let pod = self.build_pod_manifest(spec);
        let pods: kube::Api<k8s_openapi::api::core::v1::Pod> =
            kube::Api::namespaced(self.client.client.clone(), &self.client.namespace);

        let created = pods
            .create(&PostParams::default(), &pod)
            .await
            .context("failed to create workspace pod in Kubernetes")?;

        let name = created.metadata.name.unwrap_or_else(|| spec.name.clone());
        tracing::info!(pod = %name, namespace = %self.client.namespace, "created workspace pod");
        Ok(name)
    }

    async fn start_pod(&self, _name: &str) -> Result<()> {
        // No-op in Kubernetes: pods start on creation
        Ok(())
    }

    async fn stop_pod(&self, name: &str) -> Result<()> {
        // In k8s, stopping = deleting (pods are ephemeral)
        self.remove_pod(name, true, false).await
    }

    async fn remove_pod(&self, name: &str, force: bool, _remove_volumes: bool) -> Result<()> {
        let pods: kube::Api<k8s_openapi::api::core::v1::Pod> =
            kube::Api::namespaced(self.client.client.clone(), &self.client.namespace);

        let dp = if force {
            kube::api::DeleteParams {
                grace_period_seconds: Some(0),
                ..Default::default()
            }
        } else {
            kube::api::DeleteParams::default()
        };

        match pods.delete(name, &dp).await {
            Ok(_) => {
                tracing::info!(pod = %name, "deleted workspace pod");
                Ok(())
            }
            Err(kube::Error::Api(e)) if e.code == 404 => {
                tracing::debug!(pod = %name, "pod already deleted");
                Ok(())
            }
            Err(e) => Err(e).context(format!("failed to delete pod '{name}'")),
        }
    }

    async fn list_pods(&self, labels: Option<&str>) -> Result<Vec<crate::backend::PodInfo>> {
        let pods: kube::Api<k8s_openapi::api::core::v1::Pod> =
            kube::Api::namespaced(self.client.client.clone(), &self.client.namespace);

        let lp = if let Some(selector) = labels {
            kube::api::ListParams::default().labels(selector)
        } else {
            kube::api::ListParams::default()
        };

        let pod_list = pods.list(&lp).await.context("failed to list pods")?;

        Ok(pod_list
            .items
            .into_iter()
            .map(|p| kube_pod_to_info(&p))
            .collect())
    }

    async fn get_pod_info(&self, name: &str) -> Result<crate::backend::PodInfo> {
        let pods: kube::Api<k8s_openapi::api::core::v1::Pod> =
            kube::Api::namespaced(self.client.client.clone(), &self.client.namespace);

        let pod = pods
            .get(name)
            .await
            .with_context(|| format!("pod '{name}' not found"))?;

        Ok(kube_pod_to_info(&pod))
    }

    async fn exec(
        &self,
        pod_name: &str,
        container: &str,
        cmd: &[String],
        user: Option<&str>,
        workdir: Option<&str>,
    ) -> Result<i64> {
        // k8s exec doesn't natively support user/workdir, so wrap the command
        // in a shell invocation that handles them. This matches how kubectl does it.
        let effective_cmd = wrap_exec_cmd(cmd, user, workdir);
        let (code, _, _) = self
            .exec_output(pod_name, container, &effective_cmd)
            .await?;
        Ok(code)
    }

    async fn exec_output(
        &self,
        pod_name: &str,
        container: &str,
        cmd: &[String],
    ) -> Result<(i64, Vec<u8>, Vec<u8>)> {
        use tokio::io::AsyncReadExt;

        let pods: kube::Api<k8s_openapi::api::core::v1::Pod> =
            kube::Api::namespaced(self.client.client.clone(), &self.client.namespace);

        let ap = kube::api::AttachParams {
            container: Some(container.to_string()),
            stdin: false,
            stdout: true,
            stderr: true,
            tty: false,
            ..Default::default()
        };

        let mut attached = pods
            .exec(pod_name, cmd, &ap)
            .await
            .with_context(|| format!("exec into {pod_name}/{container} failed"))?;

        // Take status future before consuming streams
        let status_future = attached
            .take_status()
            .ok_or_else(|| color_eyre::eyre::eyre!("no status channel from exec"))?;

        // Collect stdout
        let mut stdout = Vec::new();
        if let Some(mut stream) = attached.stdout() {
            stream.read_to_end(&mut stdout).await.ok();
        }

        // Collect stderr
        let mut stderr = Vec::new();
        if let Some(mut stream) = attached.stderr() {
            stream.read_to_end(&mut stderr).await.ok();
        }

        // Wait for status
        let status = status_future.await;
        let code = status
            .and_then(|s| {
                s.status
                    .as_deref()
                    .map(|st| if st == "Success" { 0i64 } else { 1i64 })
            })
            .unwrap_or(1);

        Ok((code, stdout, stderr))
    }

    async fn pod_api_endpoint(&self, pod_name: &str) -> Result<String> {
        // In k8s, we use the pod's cluster IP with the well-known port.
        // The pod-api sidecar always listens on 8090.
        let pod_ip = {
            let pods: kube::Api<k8s_openapi::api::core::v1::Pod> =
                kube::Api::namespaced(self.client.client.clone(), &self.client.namespace);
            let pod = pods
                .get(pod_name)
                .await
                .with_context(|| format!("failed to get pod '{pod_name}' for endpoint"))?;
            pod.status
                .and_then(|s| s.pod_ip)
                .ok_or_else(|| color_eyre::eyre::eyre!("pod '{pod_name}' has no IP yet"))?
        };
        Ok(format!("{pod_ip}:8090"))
    }

    async fn logs(
        &self,
        pod_name: &str,
        container: &str,
        follow: bool,
        tail: Option<u64>,
    ) -> Result<String> {
        let pods: kube::Api<k8s_openapi::api::core::v1::Pod> =
            kube::Api::namespaced(self.client.client.clone(), &self.client.namespace);

        let mut lp = kube::api::LogParams {
            container: Some(container.to_string()),
            follow,
            ..Default::default()
        };
        if let Some(n) = tail {
            lp.tail_lines = Some(n as i64);
        }

        pods.logs(pod_name, &lp)
            .await
            .with_context(|| format!("failed to get logs for {pod_name}/{container}"))
    }
}

/// Wrap an exec command to run with a specific user and/or working directory.
///
/// Kubernetes exec doesn't support `--user` or `--workdir` natively (unlike
/// `podman exec`), so we wrap the command in a shell invocation that uses
/// `su` for user switching and `cd` for working directory.
fn wrap_exec_cmd(cmd: &[String], user: Option<&str>, workdir: Option<&str>) -> Vec<String> {
    match (user, workdir) {
        (None, None) => cmd.to_vec(),
        (None, Some(dir)) => {
            // Just cd to workdir, then exec the command
            let inner = cmd
                .iter()
                .map(|s| shell_escape(s))
                .collect::<Vec<_>>()
                .join(" ");
            vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                format!("cd {} && exec {inner}", shell_escape(dir)),
            ]
        }
        (Some(u), None) => {
            // Run as a different user via su
            let inner = cmd
                .iter()
                .map(|s| shell_escape(s))
                .collect::<Vec<_>>()
                .join(" ");
            vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                format!(
                    "exec su -s /bin/sh {} -c {}",
                    shell_escape(u),
                    shell_escape(&inner)
                ),
            ]
        }
        (Some(u), Some(dir)) => {
            let inner = cmd
                .iter()
                .map(|s| shell_escape(s))
                .collect::<Vec<_>>()
                .join(" ");
            vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                format!(
                    "cd {} && exec su -s /bin/sh {} -c {}",
                    shell_escape(dir),
                    shell_escape(u),
                    shell_escape(&inner)
                ),
            ]
        }
    }
}

/// Minimal shell escaping: wrap in single quotes, escaping existing single quotes.
fn shell_escape(s: &str) -> String {
    if s.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '/' || c == '.')
    {
        return s.to_string();
    }
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Convert a k8s Pod object to our backend-agnostic PodInfo.
fn kube_pod_to_info(pod: &k8s_openapi::api::core::v1::Pod) -> crate::backend::PodInfo {
    let metadata = &pod.metadata;
    let status = pod.status.as_ref();

    let phase = status.and_then(|s| s.phase.as_deref()).unwrap_or("Unknown");

    let pod_status = match phase {
        "Running" => crate::backend::PodStatus::Running,
        "Succeeded" | "Stopped" => crate::backend::PodStatus::Stopped,
        "Failed" => crate::backend::PodStatus::Failed,
        "Pending" => crate::backend::PodStatus::Pending,
        other => crate::backend::PodStatus::Unknown(other.to_string()),
    };

    let containers = status
        .and_then(|s| s.container_statuses.as_ref())
        .map(|statuses| {
            statuses
                .iter()
                .map(|cs| crate::backend::ContainerInfo {
                    name: cs.name.clone(),
                    running: cs
                        .state
                        .as_ref()
                        .map(|s| s.running.is_some())
                        .unwrap_or(false),
                    image: cs.image.clone(),
                })
                .collect()
        })
        .unwrap_or_default();

    crate::backend::PodInfo {
        name: metadata.name.clone().unwrap_or_default(),
        status: pod_status,
        labels: metadata.labels.clone().unwrap_or_default(),
        annotations: metadata.annotations.clone().unwrap_or_default(),
        containers,
    }
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

    /// Verify that security context (drop_all_caps, cap_add, no_new_privileges,
    /// privileged) is correctly translated to the k8s SecurityContext.
    #[test]
    fn test_manifest_security_context() {
        let spec = crate::backend::WorkspacePodSpec {
            name: "sec-test".to_string(),
            labels: Default::default(),
            annotations: Default::default(),
            containers: vec![crate::backend::ContainerSpec {
                name: "locked-down".to_string(),
                image: "alpine:latest".to_string(),
                command: Some(vec!["sleep".to_string(), "300".to_string()]),
                env: Default::default(),
                volume_mounts: vec![],
                workdir: None,
                user: None,
                security: crate::backend::SecurityContext {
                    privileged: false,
                    drop_all_caps: true,
                    cap_add: vec!["NET_BIND_SERVICE".to_string()],
                    no_new_privileges: true,
                    security_opts: vec![],
                },
                ports: vec![],
                healthcheck: None,
                secret_refs: vec![],
            }],
            init_containers: vec![],
            volumes: vec![],
            secrets: vec![],
            self_image: "devaipod:latest".to_string(),
        };

        let pod = build_pod_manifest_for_namespace(&spec, "test-ns");
        let containers = pod.spec.as_ref().unwrap().containers.clone();
        assert_eq!(containers.len(), 1);

        let sc = containers[0]
            .security_context
            .as_ref()
            .expect("should have security context");

        // privileged should not be set (false means omit)
        assert!(sc.privileged.is_none());

        // caps: drop ALL, add NET_BIND_SERVICE
        let caps = sc.capabilities.as_ref().expect("should have capabilities");
        assert_eq!(caps.drop.as_ref().unwrap(), &vec!["ALL".to_string()]);
        assert_eq!(
            caps.add.as_ref().unwrap(),
            &vec!["NET_BIND_SERVICE".to_string()]
        );

        // no_new_privileges maps to allowPrivilegeEscalation: false
        assert_eq!(sc.allow_privilege_escalation, Some(false));
    }

    /// Verify that healthcheck specs become k8s liveness probes.
    #[test]
    fn test_manifest_healthcheck_probe() {
        let spec = crate::backend::WorkspacePodSpec {
            name: "hc-test".to_string(),
            labels: Default::default(),
            annotations: Default::default(),
            containers: vec![crate::backend::ContainerSpec {
                name: "api".to_string(),
                image: "devaipod:latest".to_string(),
                command: None,
                env: Default::default(),
                volume_mounts: vec![],
                workdir: None,
                user: None,
                security: Default::default(),
                ports: vec![crate::backend::PortSpec {
                    container_port: 8090,
                    name: Some("api".to_string()),
                    publish: false,
                }],
                healthcheck: Some(crate::backend::HealthcheckSpec {
                    command: vec![
                        "curl".to_string(),
                        "-sf".to_string(),
                        "http://localhost:8090/healthz".to_string(),
                    ],
                    interval_secs: 5,
                    retries: 3,
                    initial_delay_secs: 10,
                }),
                secret_refs: vec![],
            }],
            init_containers: vec![],
            volumes: vec![],
            secrets: vec![],
            self_image: "devaipod:latest".to_string(),
        };

        let pod = build_pod_manifest_for_namespace(&spec, "test-ns");
        let container = &pod.spec.as_ref().unwrap().containers[0];

        let probe = container
            .liveness_probe
            .as_ref()
            .expect("should have liveness probe");

        let exec_cmd = probe
            .exec
            .as_ref()
            .expect("probe should use exec")
            .command
            .as_ref()
            .unwrap();
        assert_eq!(exec_cmd[0], "curl");
        assert_eq!(probe.period_seconds, Some(5));
        assert_eq!(probe.failure_threshold, Some(3));
        assert_eq!(probe.initial_delay_seconds, Some(10));
    }

    /// Verify that secret refs are translated to k8s secretKeyRef env vars.
    #[test]
    fn test_manifest_secret_env_refs() {
        let spec = crate::backend::WorkspacePodSpec {
            name: "secret-test".to_string(),
            labels: Default::default(),
            annotations: Default::default(),
            containers: vec![crate::backend::ContainerSpec {
                name: "agent".to_string(),
                image: "alpine:latest".to_string(),
                command: None,
                env: std::collections::BTreeMap::from([(
                    "PLAIN_VAR".to_string(),
                    "plain-value".to_string(),
                )]),
                volume_mounts: vec![],
                workdir: None,
                user: None,
                security: Default::default(),
                ports: vec![],
                healthcheck: None,
                secret_refs: vec!["api-key-secret".to_string()],
            }],
            init_containers: vec![],
            volumes: vec![],
            secrets: vec![crate::backend::SecretRef {
                name: "api-key-secret".to_string(),
                injection: crate::backend::SecretInjection::EnvVar {
                    var_name: "ANTHROPIC_API_KEY".to_string(),
                    key: "api-key".to_string(),
                },
            }],
            self_image: "devaipod:latest".to_string(),
        };

        let pod = build_pod_manifest_for_namespace(&spec, "test-ns");
        let env = pod.spec.as_ref().unwrap().containers[0]
            .env
            .as_ref()
            .unwrap();

        // Should have both the plain env var and the secret-backed one
        let plain = env.iter().find(|e| e.name == "PLAIN_VAR");
        assert!(plain.is_some());
        assert_eq!(plain.unwrap().value.as_deref(), Some("plain-value"));

        let secret_var = env.iter().find(|e| e.name == "ANTHROPIC_API_KEY");
        assert!(secret_var.is_some(), "should have secret-backed env var");
        let vf = secret_var.unwrap().value_from.as_ref().unwrap();
        let skr = vf.secret_key_ref.as_ref().unwrap();
        assert_eq!(skr.name, "api-key-secret");
        assert_eq!(skr.key, "api-key");
        assert_eq!(skr.optional, Some(true));
    }

    /// Verify that init containers with user="0" get a runAsUser security context.
    #[test]
    fn test_manifest_init_container_user() {
        let spec = crate::backend::WorkspacePodSpec {
            name: "init-test".to_string(),
            labels: Default::default(),
            annotations: Default::default(),
            containers: vec![crate::backend::ContainerSpec {
                name: "main".to_string(),
                image: "alpine:latest".to_string(),
                command: Some(vec!["sleep".to_string(), "300".to_string()]),
                env: Default::default(),
                volume_mounts: vec![],
                workdir: None,
                user: None,
                security: Default::default(),
                ports: vec![],
                healthcheck: None,
                secret_refs: vec![],
            }],
            init_containers: vec![crate::backend::InitContainerSpec {
                name: "setup".to_string(),
                image: "alpine:latest".to_string(),
                command: vec![
                    "/bin/sh".to_string(),
                    "-c".to_string(),
                    "echo hi".to_string(),
                ],
                volume_mounts: vec![],
                env: Default::default(),
                user: Some("0".to_string()),
            }],
            volumes: vec![],
            secrets: vec![],
            self_image: "devaipod:latest".to_string(),
        };

        let pod = build_pod_manifest_for_namespace(&spec, "test-ns");
        let init = pod.spec.as_ref().unwrap().init_containers.as_ref().unwrap();
        assert_eq!(init.len(), 1);

        let sc = init[0]
            .security_context
            .as_ref()
            .expect("root init container should have security context");
        assert_eq!(sc.run_as_user, Some(0));
    }

    /// Verify wrap_exec_cmd handling for user and workdir.
    #[test]
    fn test_wrap_exec_cmd() {
        // No wrapping needed
        let cmd = vec!["echo".to_string(), "hello".to_string()];
        let result = wrap_exec_cmd(&cmd, None, None);
        assert_eq!(result, cmd);

        // Workdir only
        let result = wrap_exec_cmd(&cmd, None, Some("/workspaces"));
        assert_eq!(result[0], "/bin/sh");
        assert_eq!(result[1], "-c");
        assert!(result[2].contains("cd /workspaces"));
        assert!(result[2].contains("echo hello"));

        // User only
        let result = wrap_exec_cmd(&cmd, Some("user"), None);
        assert_eq!(result[0], "/bin/sh");
        assert!(result[2].contains("su"));
        assert!(result[2].contains("user"));

        // Both
        let result = wrap_exec_cmd(&cmd, Some("user"), Some("/workspaces"));
        assert!(result[2].contains("cd /workspaces"));
        assert!(result[2].contains("su"));
    }

    /// Verify shell_escape handles safe and unsafe strings.
    #[test]
    fn test_shell_escape() {
        // Safe strings pass through
        assert_eq!(shell_escape("hello"), "hello");
        assert_eq!(shell_escape("/usr/bin/echo"), "/usr/bin/echo");

        // Unsafe strings are quoted
        assert_eq!(shell_escape("hello world"), "'hello world'");
        assert_eq!(shell_escape("it's"), "'it'\\''s'");
    }
}

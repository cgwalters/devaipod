//! Container backend abstraction for devaipod
//!
//! This module defines the [`ContainerBackend`] trait that abstracts over
//! different container runtimes (podman, Kubernetes). The trait operates at
//! the "workspace pod" level rather than individual container operations,
//! because the two backends have fundamentally different lifecycle models:
//!
//! - **Podman**: Imperative. Create pod, create volumes, run init containers
//!   as separate `podman run --rm` steps, create each container, then start.
//! - **Kubernetes**: Declarative. Build a Pod manifest with initContainers,
//!   volumes, and all container specs, then `kubectl apply`. Create = start.
//!
//! The trait captures the common operations needed by the controlplane
//! regardless of backend. Backend-specific details (init container
//! orchestration, volume provisioning, secret injection) are encapsulated
//! within each implementation.

use color_eyre::eyre::Result;
use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// Trait
// ---------------------------------------------------------------------------

/// Abstraction over container runtimes for workspace pod management.
///
/// Each workspace pod contains multiple containers (workspace, agent, gator,
/// api sidecar) sharing a network namespace. The backend is responsible for
/// translating a [`WorkspacePodSpec`] into the runtime's native representation.
#[allow(dead_code)]
#[async_trait::async_trait]
pub trait ContainerBackend: Send + Sync {
    /// Create a workspace pod from a high-level spec.
    ///
    /// This is the main entry point. The backend translates the spec into
    /// its native representation (podman pod + containers, or k8s Pod manifest)
    /// and creates it. In Kubernetes, the pod starts immediately; in podman,
    /// [`start_pod`] must be called separately.
    ///
    /// Returns the full pod name as created by the backend.
    async fn create_workspace_pod(&self, spec: &WorkspacePodSpec) -> Result<String>;

    /// Start a stopped pod. No-op in Kubernetes (pods start on creation).
    async fn start_pod(&self, name: &str) -> Result<()>;

    /// Stop a running pod.
    async fn stop_pod(&self, name: &str) -> Result<()>;

    /// Remove a pod and optionally its persistent volumes.
    async fn remove_pod(&self, name: &str, force: bool, remove_volumes: bool) -> Result<()>;

    /// List workspace pods, optionally filtered by labels.
    async fn list_pods(&self, labels: Option<&str>) -> Result<Vec<PodInfo>>;

    /// Get info about a specific pod.
    async fn get_pod_info(&self, name: &str) -> Result<PodInfo>;

    /// Execute a command in a container within a pod.
    ///
    /// Returns the exit code.
    async fn exec(
        &self,
        pod_name: &str,
        container: &str,
        cmd: &[String],
        user: Option<&str>,
        workdir: Option<&str>,
    ) -> Result<i64>;

    /// Execute a command and capture stdout/stderr.
    ///
    /// Returns (exit_code, stdout, stderr).
    async fn exec_output(
        &self,
        pod_name: &str,
        container: &str,
        cmd: &[String],
    ) -> Result<(i64, Vec<u8>, Vec<u8>)>;

    /// Get the endpoint (host:port) for the pod-api sidecar of a pod.
    ///
    /// In podman: inspects the container for the published port.
    /// In k8s: returns the Service or Pod IP endpoint.
    async fn pod_api_endpoint(&self, pod_name: &str) -> Result<String>;

    /// Stream logs from a container.
    async fn logs(
        &self,
        pod_name: &str,
        container: &str,
        follow: bool,
        tail: Option<u64>,
    ) -> Result<String>;
}

// ---------------------------------------------------------------------------
// Spec types — backend-agnostic workspace pod description
// ---------------------------------------------------------------------------

/// High-level specification for a workspace pod.
///
/// This is the backend-agnostic description of what to create. Each backend
/// translates this into its native representation. The spec deliberately
/// avoids podman-specific concepts (--secret type=env, --pod flag) and
/// k8s-specific concepts (PVC, ServiceAccount).
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct WorkspacePodSpec {
    /// Pod name (without backend-specific prefix)
    pub name: String,

    /// Labels to attach to the pod
    pub labels: BTreeMap<String, String>,

    /// Annotations (mutable metadata, e.g. task description)
    pub annotations: BTreeMap<String, String>,

    /// Container specifications (workspace, agent, gator, api, worker)
    pub containers: Vec<ContainerSpec>,

    /// Init containers to run before main containers.
    /// In podman these become `podman run --rm`; in k8s they become
    /// `initContainers` in the Pod spec.
    pub init_containers: Vec<InitContainerSpec>,

    /// Named volumes to create and mount.
    pub volumes: Vec<VolumeSpec>,

    /// Secrets to inject (backend translates to podman secrets or k8s Secrets).
    pub secrets: Vec<SecretRef>,

    /// The container image for devaipod itself (used for api sidecar).
    pub self_image: String,
}

/// Specification for a main container in the pod.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ContainerSpec {
    /// Container name suffix (e.g. "workspace", "agent", "gator")
    pub name: String,

    /// Container image
    pub image: String,

    /// Command to run (overrides image CMD)
    pub command: Option<Vec<String>>,

    /// Environment variables
    pub env: BTreeMap<String, String>,

    /// Volume mounts (volume name -> mount path)
    pub volume_mounts: Vec<VolumeMountSpec>,

    /// Working directory
    pub workdir: Option<String>,

    /// User to run as
    pub user: Option<String>,

    /// Security context
    pub security: SecurityContext,

    /// Ports to expose
    pub ports: Vec<PortSpec>,

    /// Healthcheck (translated to podman --health-cmd or k8s probe)
    pub healthcheck: Option<HealthcheckSpec>,

    /// Secrets this container needs access to.
    /// References secrets by name from WorkspacePodSpec.secrets.
    pub secret_refs: Vec<String>,
}

/// Specification for an init container.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct InitContainerSpec {
    /// Init container name
    pub name: String,

    /// Container image
    pub image: String,

    /// Command to run
    pub command: Vec<String>,

    /// Volume mounts
    pub volume_mounts: Vec<VolumeMountSpec>,

    /// Environment variables
    pub env: BTreeMap<String, String>,

    /// User to run as (Some("0") for root)
    pub user: Option<String>,
}

/// Named volume specification.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct VolumeSpec {
    /// Volume name (used to reference in mount specs)
    pub name: String,

    /// Volume type
    pub volume_type: VolumeType,
}

/// Volume type.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum VolumeType {
    /// Persistent volume (podman named volume / k8s PVC)
    Persistent,
    /// Ephemeral volume (k8s emptyDir / podman tmpfs-backed volume)
    Ephemeral,
}

/// Volume mount within a container.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct VolumeMountSpec {
    /// Volume name (references VolumeSpec.name)
    pub volume: String,
    /// Mount path inside the container
    pub mount_path: String,
    /// Mount as read-only
    pub read_only: bool,
}

/// Port to expose from a container.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct PortSpec {
    /// Container port number
    pub container_port: u16,
    /// Port name (for service discovery)
    pub name: Option<String>,
    /// Whether to publish to host (podman only; k8s uses Services)
    pub publish: bool,
}

/// Security context for a container.
#[derive(Debug, Clone, Default)]
#[allow(dead_code)]
pub struct SecurityContext {
    /// Run in privileged mode
    pub privileged: bool,
    /// Drop all capabilities
    pub drop_all_caps: bool,
    /// Capabilities to add
    pub cap_add: Vec<String>,
    /// Prevent gaining new privileges
    pub no_new_privileges: bool,
    /// SELinux/AppArmor labels to disable
    pub security_opts: Vec<String>,
}

/// Healthcheck specification.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct HealthcheckSpec {
    /// Command to run
    pub command: Vec<String>,
    /// Seconds between checks
    pub interval_secs: u32,
    /// Number of retries before marking unhealthy
    pub retries: u32,
    /// Seconds to wait before first check
    pub initial_delay_secs: u32,
}

/// Reference to a secret for injection into containers.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct SecretRef {
    /// Secret name (unique within the pod spec)
    pub name: String,
    /// How the secret is injected
    pub injection: SecretInjection,
}

/// How a secret is injected into a container.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum SecretInjection {
    /// Inject as an environment variable
    EnvVar {
        /// The env var name to set
        var_name: String,
        /// The secret key (for k8s Secret data keys)
        key: String,
    },
    /// Mount as a file
    File {
        /// Mount path inside the container
        path: String,
        /// The secret key
        key: String,
    },
}

// ---------------------------------------------------------------------------
// Pod info — backend-agnostic pod status
// ---------------------------------------------------------------------------

/// Backend-agnostic pod information.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct PodInfo {
    /// Pod name
    pub name: String,
    /// Pod status (Running, Stopped, Failed, etc.)
    pub status: PodStatus,
    /// Labels
    pub labels: BTreeMap<String, String>,
    /// Annotations
    pub annotations: BTreeMap<String, String>,
    /// Container statuses
    pub containers: Vec<ContainerInfo>,
}

/// Pod status.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub enum PodStatus {
    /// Pod is running
    Running,
    /// Pod is stopped / succeeded
    Stopped,
    /// Pod has failed
    Failed,
    /// Pod is being created / pending
    Pending,
    /// Unknown status
    Unknown(String),
}

/// Container info within a pod.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ContainerInfo {
    /// Container name
    pub name: String,
    /// Whether the container is running
    pub running: bool,
    /// Container image
    pub image: String,
}

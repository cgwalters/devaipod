//! Kubernetes integration tests
//!
//! These tests verify kube-rs client connectivity and basic pod CRUD against
//! a real cluster (e.g. minikube). They are skipped when no kubeconfig is
//! available.
//!
//! The test namespace is controlled by `DEVAIPOD_KUBE_NAMESPACE` (defaults
//! to `devaipod-test`). It is auto-created if absent and cleaned up after
//! tests complete.
//!
//! Run with: `just test-kube`

use color_eyre::eyre::{bail, Context};
use color_eyre::Result;
use std::collections::BTreeMap;

use crate::integration_test;

/// The devaipod container image to deploy in e2e tests.
/// Set via DEVAIPOD_KUBE_IMAGE env var; defaults to the published image.
const DEFAULT_KUBE_IMAGE: &str = "ghcr.io/cgwalters/devaipod:latest";

/// Check whether a working kubeconfig is available.
fn kubeconfig_available() -> bool {
    if let Ok(path) = std::env::var("KUBECONFIG") {
        return std::path::Path::new(&path).is_file();
    }
    if let Ok(home) = std::env::var("HOME") {
        return std::path::Path::new(&home).join(".kube/config").is_file();
    }
    false
}

/// Get the test namespace from config or environment.
///
/// Priority: DEVAIPOD_KUBE_NAMESPACE env var > default "devaipod-test".
fn test_namespace() -> String {
    std::env::var("DEVAIPOD_KUBE_NAMESPACE").unwrap_or_else(|_| "devaipod-test".to_string())
}

/// Build a kube::Client from default kubeconfig, installing the rustls
/// crypto provider first.
async fn make_client() -> Result<kube::Client> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    kube::Client::try_default()
        .await
        .context("failed to create kube client from default kubeconfig")
}

/// Ensure a namespace exists, creating it if absent (same logic as
/// src/kube.rs ensure_namespace, duplicated here to avoid coupling
/// the test crate to the main binary's internal API).
async fn ensure_namespace(client: &kube::Client, name: &str) -> Result<()> {
    use k8s_openapi::api::core::v1::Namespace;
    use kube::api::{ObjectMeta, PostParams};

    let ns_api: kube::Api<Namespace> = kube::Api::all(client.clone());

    match ns_api.get(name).await {
        Ok(_) => {
            eprintln!("namespace {name} already exists");
            return Ok(());
        }
        Err(kube::Error::Api(e)) if e.code == 404 => {}
        Err(e) => return Err(e).context(format!("failed to check namespace '{name}'")),
    }

    let ns = Namespace {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            labels: Some(BTreeMap::from([(
                "io.devaipod/managed".to_string(),
                "true".to_string(),
            )])),
            ..Default::default()
        },
        ..Default::default()
    };

    match ns_api.create(&PostParams::default(), &ns).await {
        Ok(_) => {
            eprintln!("created namespace {name}");
            Ok(())
        }
        Err(kube::Error::Api(e)) if e.code == 409 => {
            eprintln!("namespace {name} created concurrently");
            Ok(())
        }
        Err(e) => Err(e).context(format!("failed to create namespace '{name}'")),
    }
}

// -----------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------

/// Verify we can connect to the cluster and read the server version.
fn test_kube_connect() -> Result<()> {
    if !kubeconfig_available() {
        eprintln!("skipping: no kubeconfig available");
        return Ok(());
    }

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        let client = make_client().await?;
        let version = client.apiserver_version().await?;
        eprintln!(
            "connected to cluster, server version: {}.{}",
            version.major, version.minor
        );
        assert!(!version.major.is_empty());
        Ok(())
    })
}
integration_test!(test_kube_connect);

/// Ensure the configured namespace exists (auto-create if absent),
/// then create a pod, wait for Running, list by label, and clean up
/// the pod. The namespace is left in place for other tests.
fn test_kube_pod_lifecycle() -> Result<()> {
    if !kubeconfig_available() {
        eprintln!("skipping: no kubeconfig available");
        return Ok(());
    }

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        use k8s_openapi::api::core::v1::{Container, Pod, PodSpec};
        use kube::api::{DeleteParams, ListParams, ObjectMeta, PostParams};

        let client = make_client().await?;
        let ns_name = test_namespace();

        // Ensure namespace exists (auto-create if absent)
        ensure_namespace(&client, &ns_name).await?;

        let run_id = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            & 0xFFFF;
        let pod_name = format!("lifecycle-{run_id:x}");

        // Create pod
        let pods: kube::Api<Pod> = kube::Api::namespaced(client.clone(), &ns_name);
        let pod = Pod {
            metadata: ObjectMeta {
                name: Some(pod_name.clone()),
                labels: Some(BTreeMap::from([
                    ("io.devaipod/managed".to_string(), "true".to_string()),
                    ("io.devaipod/test".to_string(), "true".to_string()),
                ])),
                ..Default::default()
            },
            spec: Some(PodSpec {
                containers: vec![Container {
                    name: "test".to_string(),
                    image: Some("alpine:latest".to_string()),
                    command: Some(vec!["sleep".to_string(), "300".to_string()]),
                    ..Default::default()
                }],
                restart_policy: Some("Never".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };

        pods.create(&PostParams::default(), &pod)
            .await
            .context("failed to create test pod")?;
        eprintln!("created pod {pod_name} in namespace {ns_name}");

        // Wait for Running (up to 120s for image pull)
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
        loop {
            let p = pods.get(&pod_name).await?;
            let phase = p
                .status
                .as_ref()
                .and_then(|s| s.phase.as_deref())
                .unwrap_or("Unknown");

            if phase == "Running" {
                eprintln!("pod {pod_name} is Running");
                break;
            }
            if phase == "Failed" || phase == "Succeeded" {
                // Clean up before bailing
                let _ = pods.delete(&pod_name, &DeleteParams::default()).await;
                color_eyre::eyre::bail!("pod entered terminal phase: {phase}");
            }
            if std::time::Instant::now() > deadline {
                let _ = pods.delete(&pod_name, &DeleteParams::default()).await;
                color_eyre::eyre::bail!("pod did not reach Running within 120s (phase: {phase})");
            }
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }

        // Verify label-based listing works
        let lp = ListParams::default().labels("io.devaipod/test=true");
        let pod_list = pods.list(&lp).await?;
        let found = pod_list.items.iter().any(|p| {
            p.metadata
                .name
                .as_deref()
                .map(|n| n == pod_name)
                .unwrap_or(false)
        });
        assert!(found, "created pod not found in label-filtered list");
        eprintln!(
            "label selector found {} pod(s) with io.devaipod/test=true",
            pod_list.items.len()
        );

        // Clean up pod (force-delete, don't wait for graceful shutdown)
        pods.delete(
            &pod_name,
            &DeleteParams {
                grace_period_seconds: Some(0),
                ..Default::default()
            },
        )
        .await?;
        eprintln!("deleted pod {pod_name}");

        Ok(())
    })
}
integration_test!(test_kube_pod_lifecycle);

/// Get the container image to use for kube e2e tests.
fn kube_test_image() -> String {
    std::env::var("DEVAIPOD_KUBE_IMAGE").unwrap_or_else(|_| DEFAULT_KUBE_IMAGE.to_string())
}

/// Check if the devaipod image is available in the cluster.
///
/// Tries to verify by checking if minikube has the image loaded.
/// Falls back to assuming it's available (for remote clusters with
/// registry access).
fn kube_image_available() -> bool {
    // If the user explicitly set the image, trust them
    if std::env::var("DEVAIPOD_KUBE_IMAGE").is_ok() {
        return true;
    }
    // Check minikube image list
    let output = std::process::Command::new("minikube")
        .args(["image", "ls"])
        .output();
    match output {
        Ok(o) if o.status.success() => {
            let images = String::from_utf8_lossy(&o.stdout);
            images.contains("devaipod")
        }
        _ => {
            // No minikube or command failed -- try /tmp/minikube
            let output = std::process::Command::new("/tmp/minikube")
                .args(["image", "ls"])
                .output();
            match output {
                Ok(o) if o.status.success() => {
                    String::from_utf8_lossy(&o.stdout).contains("devaipod")
                }
                _ => false,
            }
        }
    }
}

/// Deploy devaipod as a controlplane pod in Kubernetes, verify the health
/// endpoint serves, then clean up.
///
/// This is the real e2e test: it proves devaipod can run as a pod in a
/// Kubernetes cluster and serve its web UI. The image must be pre-loaded
/// into the cluster (e.g. `minikube image load`).
fn test_kube_controlplane_health() -> Result<()> {
    if !kubeconfig_available() {
        eprintln!("skipping: no kubeconfig available");
        return Ok(());
    }
    if !kube_image_available() {
        eprintln!("skipping: devaipod image not available in cluster");
        eprintln!("hint: run `podman save --format docker-archive -o /tmp/d.tar ghcr.io/cgwalters/devaipod:latest && minikube image load /tmp/d.tar`");
        return Ok(());
    }

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        use k8s_openapi::api::core::v1::{
            ConfigMap, Container, ContainerPort, EnvVar, Pod, PodSpec, Volume, VolumeMount,
        };
        use kube::api::{DeleteParams, ObjectMeta, PostParams};

        let client = make_client().await?;
        let ns_name = test_namespace();
        let image = kube_test_image();

        ensure_namespace(&client, &ns_name).await?;

        let run_id = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            & 0xFFFF;
        let pod_name = format!("controlplane-{run_id:x}");
        let cm_name = format!("config-{run_id:x}");

        // Create a minimal config ConfigMap
        let cms: kube::Api<ConfigMap> = kube::Api::namespaced(client.clone(), &ns_name);
        let cm = ConfigMap {
            metadata: ObjectMeta {
                name: Some(cm_name.clone()),
                ..Default::default()
            },
            data: Some(BTreeMap::from([(
                "devaipod.toml".to_string(),
                "# Minimal config for kube e2e test\n".to_string(),
            )])),
            ..Default::default()
        };
        cms.create(&PostParams::default(), &cm).await?;

        // Create the controlplane pod
        let pods: kube::Api<Pod> = kube::Api::namespaced(client.clone(), &ns_name);
        let pod = Pod {
            metadata: ObjectMeta {
                name: Some(pod_name.clone()),
                labels: Some(BTreeMap::from([
                    ("io.devaipod/managed".to_string(), "true".to_string()),
                    ("io.devaipod/test".to_string(), "true".to_string()),
                    ("app".to_string(), "devaipod".to_string()),
                ])),
                ..Default::default()
            },
            spec: Some(PodSpec {
                containers: vec![Container {
                    name: "devaipod".to_string(),
                    image: Some(image.clone()),
                    image_pull_policy: Some("Never".to_string()),
                    ports: Some(vec![ContainerPort {
                        container_port: 8080,
                        name: Some("web".to_string()),
                        ..Default::default()
                    }]),
                    env: Some(vec![
                        EnvVar {
                            name: "DEVAIPOD_CONTAINER".to_string(),
                            value: Some("1".to_string()),
                            ..Default::default()
                        },
                        EnvVar {
                            name: "DEVAIPOD_CONTAINER_IMAGE".to_string(),
                            value: Some(image.clone()),
                            ..Default::default()
                        },
                        EnvVar {
                            name: "DEVAIPOD_HOST_MODE".to_string(),
                            value: Some("1".to_string()),
                            ..Default::default()
                        },
                    ]),
                    volume_mounts: Some(vec![VolumeMount {
                        name: "config".to_string(),
                        mount_path: "/root/.config/devaipod.toml".to_string(),
                        sub_path: Some("devaipod.toml".to_string()),
                        read_only: Some(true),
                        ..Default::default()
                    }]),
                    ..Default::default()
                }],
                volumes: Some(vec![Volume {
                    name: "config".to_string(),
                    config_map: Some(k8s_openapi::api::core::v1::ConfigMapVolumeSource {
                        name: cm_name.clone(),
                        ..Default::default()
                    }),
                    ..Default::default()
                }]),
                restart_policy: Some("Never".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };

        pods.create(&PostParams::default(), &pod)
            .await
            .context("failed to create controlplane pod")?;
        eprintln!("created controlplane pod {pod_name} with image {image}");

        // Cleanup helper
        let cleanup = |pods: kube::Api<Pod>,
                       cms: kube::Api<ConfigMap>,
                       pod_name: String,
                       cm_name: String| async move {
            let dp = DeleteParams {
                grace_period_seconds: Some(0),
                ..Default::default()
            };
            let _ = pods.delete(&pod_name, &dp).await;
            let _ = cms.delete(&cm_name, &DeleteParams::default()).await;
        };

        // Wait for Running (up to 60s -- image is pre-loaded)
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        loop {
            let p = pods.get(&pod_name).await?;
            let phase = p
                .status
                .as_ref()
                .and_then(|s| s.phase.as_deref())
                .unwrap_or("Unknown");

            if phase == "Running" {
                eprintln!("pod {pod_name} is Running");
                break;
            }
            if phase == "Failed" || phase == "Succeeded" {
                // Grab logs before cleanup
                let logs = pods
                    .logs(&pod_name, &kube::api::LogParams::default())
                    .await
                    .unwrap_or_default();
                cleanup(pods.clone(), cms.clone(), pod_name.clone(), cm_name.clone()).await;
                bail!("controlplane pod entered terminal phase: {phase}\nlogs:\n{logs}");
            }
            if std::time::Instant::now() > deadline {
                let logs = pods
                    .logs(&pod_name, &kube::api::LogParams::default())
                    .await
                    .unwrap_or_default();
                cleanup(pods.clone(), cms.clone(), pod_name.clone(), cm_name.clone()).await;
                bail!(
                    "controlplane pod did not reach Running within 60s (phase: {phase})\nlogs:\n{logs}"
                );
            }
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }

        // Wait for the web server to be ready by polling exec curl
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        let mut health_ok = false;
        while std::time::Instant::now() < deadline {
            // Use kubectl exec to curl the health endpoint from inside the pod
            let result = std::process::Command::new("kubectl")
                .args([
                    "exec",
                    "-n",
                    &ns_name,
                    &pod_name,
                    "--",
                    "curl",
                    "-sf",
                    "http://localhost:8080/_devaipod/health",
                ])
                .output();

            // Also try /tmp/kubectl
            let result = match result {
                Ok(o) if o.status.success() => Ok(o),
                _ => std::process::Command::new("/tmp/kubectl")
                    .args([
                        "exec",
                        "-n",
                        &ns_name,
                        &pod_name,
                        "--",
                        "curl",
                        "-sf",
                        "http://localhost:8080/_devaipod/health",
                    ])
                    .output(),
            };

            if let Ok(output) = result {
                if output.status.success() {
                    let body = String::from_utf8_lossy(&output.stdout);
                    eprintln!("health endpoint returned: {}", body.trim());
                    health_ok = true;
                    break;
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }

        if !health_ok {
            let logs = pods
                .logs(&pod_name, &kube::api::LogParams::default())
                .await
                .unwrap_or_default();
            cleanup(pods.clone(), cms.clone(), pod_name.clone(), cm_name.clone()).await;
            bail!("health endpoint never responded\nlogs:\n{logs}");
        }

        eprintln!("controlplane health endpoint verified in k8s");

        // Clean up
        cleanup(pods, cms, pod_name.clone(), cm_name.clone()).await;
        eprintln!("cleaned up pod {pod_name} and config {cm_name}");

        Ok(())
    })
}
integration_test!(test_kube_controlplane_health);

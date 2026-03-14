//! Kubernetes integration tests
//!
//! These tests verify kube-rs client connectivity and basic pod CRUD against
//! a real cluster (e.g. minikube). They are skipped when no kubeconfig is
//! available.
//!
//! Run with: `just test-kube`

use color_eyre::eyre::Context;
use color_eyre::Result;
use std::collections::BTreeMap;

use crate::integration_test;

/// Check whether a working kubeconfig is available.
///
/// Returns true if ~/.kube/config exists or KUBECONFIG is set to a
/// readable file. Tests call this to skip gracefully when no cluster
/// is configured.
fn kubeconfig_available() -> bool {
    if let Ok(path) = std::env::var("KUBECONFIG") {
        return std::path::Path::new(&path).is_file();
    }
    if let Ok(home) = std::env::var("HOME") {
        return std::path::Path::new(&home).join(".kube/config").is_file();
    }
    false
}

/// Build a kube::Client from default kubeconfig, installing the rustls
/// crypto provider first (required when no other crate has done it).
async fn make_client() -> Result<kube::Client> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    kube::Client::try_default()
        .await
        .context("failed to create kube client from default kubeconfig")
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

/// Create a pod in a fresh namespace, wait for Running, list by label,
/// then clean up both pod and namespace.
fn test_kube_pod_lifecycle() -> Result<()> {
    if !kubeconfig_available() {
        eprintln!("skipping: no kubeconfig available");
        return Ok(());
    }

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        use k8s_openapi::api::core::v1::{Container, Namespace, Pod, PodSpec};
        use kube::api::{DeleteParams, ListParams, ObjectMeta, PostParams};

        let client = make_client().await?;

        // Use a unique namespace per test run to avoid collisions
        let run_id = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            & 0xFFFF;
        let ns_name = format!("devaipod-test-{run_id:x}");
        let pod_name = format!("lifecycle-{run_id:x}");

        // Create namespace
        let ns_api: kube::Api<Namespace> = kube::Api::all(client.clone());
        let ns = Namespace {
            metadata: ObjectMeta {
                name: Some(ns_name.clone()),
                labels: Some(BTreeMap::from([(
                    "io.devaipod/test".to_string(),
                    "true".to_string(),
                )])),
                ..Default::default()
            },
            ..Default::default()
        };
        ns_api
            .create(&PostParams::default(), &ns)
            .await
            .context("failed to create test namespace")?;
        eprintln!("created namespace {ns_name}");

        // From here, always clean up the namespace on exit
        let cleanup = |client: kube::Client, ns: String| async move {
            let ns_api: kube::Api<Namespace> = kube::Api::all(client);
            let _ = ns_api.delete(&ns, &DeleteParams::default()).await;
            eprintln!("deleted namespace {ns}");
        };

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

        if let Err(e) = pods.create(&PostParams::default(), &pod).await {
            cleanup(client.clone(), ns_name.clone()).await;
            return Err(e).context("failed to create test pod");
        }
        eprintln!("created pod {pod_name}");

        // Wait for Running (up to 120s for image pull)
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
        loop {
            let p = match pods.get(&pod_name).await {
                Ok(p) => p,
                Err(e) => {
                    cleanup(client.clone(), ns_name.clone()).await;
                    return Err(e.into());
                }
            };
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
                cleanup(client.clone(), ns_name.clone()).await;
                color_eyre::eyre::bail!("pod entered terminal phase: {phase}");
            }
            if std::time::Instant::now() > deadline {
                cleanup(client.clone(), ns_name.clone()).await;
                color_eyre::eyre::bail!("pod did not reach Running within 120s (phase: {phase})");
            }
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }

        // Verify we can list pods with label selector
        let lp = ListParams::default().labels("io.devaipod/test=true");
        let pod_list = pods.list(&lp).await?;
        let found = pod_list.items.iter().any(|p| {
            p.metadata
                .name
                .as_deref()
                .map(|n| n == pod_name)
                .unwrap_or(false)
        });
        if !found {
            cleanup(client.clone(), ns_name.clone()).await;
            color_eyre::eyre::bail!("created pod not found in label-filtered list");
        }
        eprintln!(
            "label selector found {} pod(s) with io.devaipod/test=true",
            pod_list.items.len()
        );

        // Clean up: delete pod (force) then namespace
        let dp = DeleteParams {
            grace_period_seconds: Some(0),
            ..Default::default()
        };
        let _ = pods.delete(&pod_name, &dp).await;
        eprintln!("deleted pod {pod_name}");

        cleanup(client.clone(), ns_name.clone()).await;

        Ok(())
    })
}
integration_test!(test_kube_pod_lifecycle);

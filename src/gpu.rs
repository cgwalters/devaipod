//! GPU detection and passthrough for containers
//!
//! This module provides GPU detection and configuration for passing GPUs
//! through to containers. Supports:
//! - NVIDIA GPUs (via CDI or direct device passthrough)
//! - AMD GPUs (via direct device passthrough)

use std::fs;
use std::path::Path;

/// GPU vendor types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpuVendor {
    Nvidia,
    Amd,
}

/// Information about available GPUs on the host
#[derive(Debug, Clone, Default)]
pub struct GpuInfo {
    /// NVIDIA GPU device paths (e.g., /dev/nvidia0)
    pub nvidia_devices: Vec<String>,
    /// AMD GPU render device paths (e.g., /dev/dri/renderD128)
    pub amd_devices: Vec<String>,
    /// Whether NVIDIA CDI (Container Device Interface) is available
    pub has_nvidia_cdi: bool,
    /// Whether /dev/kfd exists (required for AMD ROCm)
    pub has_amd_kfd: bool,
}

impl GpuInfo {
    /// Detect available GPUs on the host system
    pub fn detect() -> Self {
        let mut info = Self::default();

        // Detect NVIDIA GPUs
        for i in 0..16 {
            let device = format!("/dev/nvidia{}", i);
            if Path::new(&device).exists() {
                info.nvidia_devices.push(device);
            }
        }

        // Check for NVIDIA CDI support
        info.has_nvidia_cdi = Path::new("/run/cdi/nvidia.yaml").exists()
            || Path::new("/etc/cdi/nvidia.yaml").exists();

        // Detect AMD GPUs via DRI render nodes
        info.has_amd_kfd = Path::new("/dev/kfd").exists();
        if let Ok(entries) = fs::read_dir("/dev/dri") {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                if name_str.starts_with("renderD") {
                    info.amd_devices
                        .push(entry.path().to_string_lossy().to_string());
                }
            }
        }

        info
    }

    /// Check if any GPUs are available
    pub fn has_gpus(&self) -> bool {
        !self.nvidia_devices.is_empty() || (!self.amd_devices.is_empty() && self.has_amd_kfd)
    }

    /// Get the detected GPU vendor(s)
    pub fn vendors(&self) -> Vec<GpuVendor> {
        let mut vendors = Vec::new();
        if !self.nvidia_devices.is_empty() {
            vendors.push(GpuVendor::Nvidia);
        }
        if !self.amd_devices.is_empty() && self.has_amd_kfd {
            vendors.push(GpuVendor::Amd);
        }
        vendors
    }
}

/// GPU configuration for containers
#[derive(Debug, Clone, Default)]
pub struct GpuConfig {
    /// Device paths to pass through (e.g., /dev/nvidia0, /dev/dri/renderD128)
    pub devices: Vec<String>,
    /// CDI device names (e.g., nvidia.com/gpu=all)
    pub cdi_devices: Vec<String>,
    /// Additional security options needed (e.g., seccomp=unconfined for AMD)
    pub security_opts: Vec<String>,
    /// Additional groups to add (e.g., video for AMD)
    pub groups: Vec<String>,
}

impl GpuConfig {
    /// Create GPU config for NVIDIA GPUs
    pub fn nvidia(info: &GpuInfo) -> Self {
        if info.has_nvidia_cdi {
            // Prefer CDI for better rootless support
            Self {
                cdi_devices: vec!["nvidia.com/gpu=all".to_string()],
                security_opts: vec!["label=disable".to_string()],
                ..Default::default()
            }
        } else {
            // Fallback to direct device passthrough
            let mut devices = info.nvidia_devices.clone();
            // Also need control devices
            for dev in &["/dev/nvidiactl", "/dev/nvidia-uvm", "/dev/nvidia-modeset"] {
                if Path::new(dev).exists() {
                    devices.push(dev.to_string());
                }
            }
            Self {
                devices,
                security_opts: vec!["label=disable".to_string()],
                ..Default::default()
            }
        }
    }

    /// Create GPU config for AMD GPUs
    pub fn amd(info: &GpuInfo) -> Self {
        let mut devices = info.amd_devices.clone();
        if info.has_amd_kfd {
            devices.push("/dev/kfd".to_string());
        }
        Self {
            devices,
            security_opts: vec!["seccomp=unconfined".to_string()],
            groups: vec!["video".to_string()],
            ..Default::default()
        }
    }

    /// Create GPU config based on detected hardware
    pub fn from_detected(info: &GpuInfo) -> Option<Self> {
        // Prefer NVIDIA if both are present
        if !info.nvidia_devices.is_empty() {
            Some(Self::nvidia(info))
        } else if !info.amd_devices.is_empty() && info.has_amd_kfd {
            Some(Self::amd(info))
        } else {
            None
        }
    }

    /// Check if this config has any GPU devices
    pub fn has_devices(&self) -> bool {
        !self.devices.is_empty() || !self.cdi_devices.is_empty()
    }

    /// Get podman arguments for this GPU config
    pub fn to_podman_args(&self) -> Vec<String> {
        let mut args = Vec::new();

        // Add CDI devices
        for cdi in &self.cdi_devices {
            args.push("--device".to_string());
            args.push(cdi.clone());
        }

        // Add regular devices
        for device in &self.devices {
            args.push("--device".to_string());
            args.push(device.clone());
        }

        // Add security options
        for opt in &self.security_opts {
            args.push("--security-opt".to_string());
            args.push(opt.clone());
        }

        // Add groups
        for group in &self.groups {
            args.push("--group-add".to_string());
            args.push(group.clone());
        }

        args
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gpu_info_default() {
        let info = GpuInfo::default();
        assert!(!info.has_gpus());
        assert!(info.vendors().is_empty());
    }

    #[test]
    fn test_nvidia_config_with_cdi() {
        let info = GpuInfo {
            nvidia_devices: vec!["/dev/nvidia0".to_string()],
            has_nvidia_cdi: true,
            ..Default::default()
        };
        let config = GpuConfig::nvidia(&info);
        assert_eq!(config.cdi_devices, vec!["nvidia.com/gpu=all"]);
        assert!(config.devices.is_empty());
    }

    #[test]
    fn test_nvidia_config_without_cdi() {
        let info = GpuInfo {
            nvidia_devices: vec!["/dev/nvidia0".to_string()],
            has_nvidia_cdi: false,
            ..Default::default()
        };
        let config = GpuConfig::nvidia(&info);
        assert!(config.cdi_devices.is_empty());
        assert!(config.devices.contains(&"/dev/nvidia0".to_string()));
    }

    #[test]
    fn test_amd_config() {
        let info = GpuInfo {
            amd_devices: vec!["/dev/dri/renderD128".to_string()],
            has_amd_kfd: true,
            ..Default::default()
        };
        let config = GpuConfig::amd(&info);
        assert!(config.devices.contains(&"/dev/dri/renderD128".to_string()));
        assert!(config.devices.contains(&"/dev/kfd".to_string()));
        assert!(config.groups.contains(&"video".to_string()));
    }

    #[test]
    fn test_to_podman_args() {
        let config = GpuConfig {
            cdi_devices: vec!["nvidia.com/gpu=all".to_string()],
            security_opts: vec!["label=disable".to_string()],
            ..Default::default()
        };
        let args = config.to_podman_args();
        assert!(args.contains(&"--device".to_string()));
        assert!(args.contains(&"nvidia.com/gpu=all".to_string()));
        assert!(args.contains(&"--security-opt".to_string()));
        assert!(args.contains(&"label=disable".to_string()));
    }
}

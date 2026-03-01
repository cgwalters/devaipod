//! Integration test modules

pub mod advisor;
pub mod cli;
pub mod container;
pub mod orchestration;
pub mod pod_api;
pub mod ssh;
pub mod webui;

// Re-export WebFixture for cleanup in main
pub use webui::WebFixture;

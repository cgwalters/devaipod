//! Constants used throughout devc

/// Marker label for all devc-managed resources (volumes, containers, pods)
pub const LABEL_MARKER: &str = "cgwalters.devc=1";

/// Label key for source URL/path
pub const LABEL_KEY_SOURCE: &str = "cgwalters.devc.source";

/// Label key for git ref/branch
pub const LABEL_KEY_REF: &str = "cgwalters.devc.ref";

/// Label key for workspace description
pub const LABEL_KEY_DESCRIPTION: &str = "cgwalters.devc.description";

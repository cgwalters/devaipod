//! Git forge (GitHub, GitLab, Forgejo, etc.) integration
//!
//! This module provides abstractions for working with git hosting platforms,
//! including parsing PR/MR URLs and fetching metadata.

use color_eyre::eyre::{bail, Context, Result};
use serde::{Deserialize, Serialize};

/// Supported git forge types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ForgeType {
    GitHub,
    GitLab,
    Forgejo,
    Gitea,
}

impl std::fmt::Display for ForgeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ForgeType::GitHub => write!(f, "github"),
            ForgeType::GitLab => write!(f, "gitlab"),
            ForgeType::Forgejo => write!(f, "forgejo"),
            ForgeType::Gitea => write!(f, "gitea"),
        }
    }
}

/// A parsed pull/merge request reference
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PullRequestRef {
    /// The forge type (github, gitlab, etc.)
    pub forge_type: ForgeType,
    /// The forge host (e.g., "github.com", "gitlab.com", "codeberg.org")
    pub host: String,
    /// Repository owner/organization
    pub owner: String,
    /// Repository name
    pub repo: String,
    /// PR/MR number
    pub number: u64,
}

impl PullRequestRef {
    /// Get the upstream repository URL (HTTPS)
    pub fn upstream_url(&self) -> String {
        format!("https://{}/{}/{}.git", self.host, self.owner, self.repo)
    }

    /// Get a short display string like "owner/repo#123"
    pub fn short_display(&self) -> String {
        format!("{}/{}#{}", self.owner, self.repo, self.number)
    }

    /// Get the host without the protocol
    pub fn host_repo(&self) -> String {
        format!("{}/{}/{}", self.host, self.owner, self.repo)
    }
}

/// Metadata about a pull/merge request
#[derive(Debug, Clone)]
pub struct PullRequestInfo {
    /// The PR reference
    pub pr_ref: PullRequestRef,
    /// PR title
    pub title: String,
    /// The clone URL for the head (source) repository
    pub head_clone_url: String,
    /// The ref to checkout (branch name or commit SHA)
    pub head_ref: String,
    /// The commit SHA of the head
    pub head_sha: String,
}

impl PullRequestInfo {
    /// Get metadata suitable for pod labels
    pub fn to_labels(&self) -> Vec<(String, String)> {
        vec![
            (
                "io.devaipod.forge".to_string(),
                self.pr_ref.forge_type.to_string(),
            ),
            (
                "io.devaipod.repo".to_string(),
                self.pr_ref.host_repo(),
            ),
            (
                "io.devaipod.pr".to_string(),
                self.pr_ref.number.to_string(),
            ),
            (
                "io.devaipod.commit".to_string(),
                self.head_sha.clone(),
            ),
        ]
    }
}

/// Parse a URL to extract PR/MR information
///
/// Supports:
/// - GitHub: https://github.com/owner/repo/pull/123
/// - GitLab: https://gitlab.com/owner/repo/-/merge_requests/123
/// - Forgejo/Gitea: https://codeberg.org/owner/repo/pulls/123
///
/// Returns None if the URL doesn't match a known PR/MR pattern.
pub fn parse_pr_url(url: &str) -> Option<PullRequestRef> {
    let url = url.trim().trim_end_matches('/');

    // Try to parse as URL
    let parsed = url::Url::parse(url).ok()?;
    let host = parsed.host_str()?.to_string();
    let path_segments: Vec<&str> = parsed.path().trim_start_matches('/').split('/').collect();

    // GitHub: /owner/repo/pull/123
    if path_segments.len() >= 4 && path_segments[2] == "pull" {
        let number: u64 = path_segments[3].parse().ok()?;
        return Some(PullRequestRef {
            forge_type: if host.contains("github") {
                ForgeType::GitHub
            } else {
                // Could be a GitHub Enterprise instance
                ForgeType::GitHub
            },
            host,
            owner: path_segments[0].to_string(),
            repo: path_segments[1].to_string(),
            number,
        });
    }

    // GitLab: /owner/repo/-/merge_requests/123
    if path_segments.len() >= 5
        && path_segments[2] == "-"
        && path_segments[3] == "merge_requests"
    {
        let number: u64 = path_segments[4].parse().ok()?;
        return Some(PullRequestRef {
            forge_type: ForgeType::GitLab,
            host,
            owner: path_segments[0].to_string(),
            repo: path_segments[1].to_string(),
            number,
        });
    }

    // Forgejo/Gitea: /owner/repo/pulls/123
    if path_segments.len() >= 4 && path_segments[2] == "pulls" {
        let number: u64 = path_segments[3].parse().ok()?;
        return Some(PullRequestRef {
            forge_type: if host.contains("codeberg") || host.contains("forgejo") {
                ForgeType::Forgejo
            } else if host.contains("gitea") {
                ForgeType::Gitea
            } else {
                // Default to Forgejo for unknown hosts with /pulls/ pattern
                ForgeType::Forgejo
            },
            host,
            owner: path_segments[0].to_string(),
            repo: path_segments[1].to_string(),
            number,
        });
    }

    None
}

/// Fetch PR metadata from the forge API
pub async fn fetch_pr_info(pr_ref: &PullRequestRef) -> Result<PullRequestInfo> {
    match pr_ref.forge_type {
        ForgeType::GitHub => fetch_github_pr(pr_ref).await,
        ForgeType::GitLab => fetch_gitlab_mr(pr_ref).await,
        ForgeType::Forgejo | ForgeType::Gitea => fetch_forgejo_pr(pr_ref).await,
    }
}

/// Fetch GitHub PR metadata
async fn fetch_github_pr(pr_ref: &PullRequestRef) -> Result<PullRequestInfo> {
    let api_url = if pr_ref.host == "github.com" {
        format!(
            "https://api.github.com/repos/{}/{}/pulls/{}",
            pr_ref.owner, pr_ref.repo, pr_ref.number
        )
    } else {
        // GitHub Enterprise
        format!(
            "https://{}/api/v3/repos/{}/{}/pulls/{}",
            pr_ref.host, pr_ref.owner, pr_ref.repo, pr_ref.number
        )
    };

    let client = reqwest::Client::new();
    let mut request = client
        .get(&api_url)
        .header("User-Agent", "devaipod")
        .header("Accept", "application/vnd.github+json");

    // Use GITHUB_TOKEN if available
    if let Ok(token) = std::env::var("GITHUB_TOKEN") {
        request = request.header("Authorization", format!("Bearer {}", token));
    }

    let response = request.send().await.context("Failed to fetch PR from GitHub API")?;

    if !response.status().is_success() {
        bail!(
            "GitHub API returned {}: {}",
            response.status(),
            response.text().await.unwrap_or_default()
        );
    }

    let json: serde_json::Value = response.json().await.context("Failed to parse GitHub API response")?;

    let title = json
        .get("title")
        .and_then(|v| v.as_str())
        .unwrap_or("Untitled")
        .to_string();

    let head = json.get("head").ok_or_else(|| color_eyre::eyre::eyre!("Missing 'head' in PR response"))?;

    let head_clone_url = head
        .get("repo")
        .and_then(|r| r.get("clone_url"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| color_eyre::eyre::eyre!("Missing head repo clone_url"))?
        .to_string();

    let head_ref = head
        .get("ref")
        .and_then(|v| v.as_str())
        .ok_or_else(|| color_eyre::eyre::eyre!("Missing head ref"))?
        .to_string();

    let head_sha = head
        .get("sha")
        .and_then(|v| v.as_str())
        .ok_or_else(|| color_eyre::eyre::eyre!("Missing head sha"))?
        .to_string();

    Ok(PullRequestInfo {
        pr_ref: pr_ref.clone(),
        title,
        head_clone_url,
        head_ref,
        head_sha,
    })
}

/// Fetch GitLab MR metadata
async fn fetch_gitlab_mr(pr_ref: &PullRequestRef) -> Result<PullRequestInfo> {
    let project_path = format!("{}/{}", pr_ref.owner, pr_ref.repo);
    let encoded_path = urlencoding::encode(&project_path);

    let api_url = if pr_ref.host == "gitlab.com" {
        format!(
            "https://gitlab.com/api/v4/projects/{}/merge_requests/{}",
            encoded_path, pr_ref.number
        )
    } else {
        format!(
            "https://{}/api/v4/projects/{}/merge_requests/{}",
            pr_ref.host, encoded_path, pr_ref.number
        )
    };

    let client = reqwest::Client::new();
    let mut request = client
        .get(&api_url)
        .header("User-Agent", "devaipod");

    // Use GITLAB_TOKEN if available
    if let Ok(token) = std::env::var("GITLAB_TOKEN") {
        request = request.header("PRIVATE-TOKEN", token);
    }

    let response = request.send().await.context("Failed to fetch MR from GitLab API")?;

    if !response.status().is_success() {
        bail!(
            "GitLab API returned {}: {}",
            response.status(),
            response.text().await.unwrap_or_default()
        );
    }

    let json: serde_json::Value = response.json().await.context("Failed to parse GitLab API response")?;

    let title = json
        .get("title")
        .and_then(|v| v.as_str())
        .unwrap_or("Untitled")
        .to_string();

    let source_branch = json
        .get("source_branch")
        .and_then(|v| v.as_str())
        .ok_or_else(|| color_eyre::eyre::eyre!("Missing source_branch"))?
        .to_string();

    let head_sha = json
        .get("sha")
        .and_then(|v| v.as_str())
        .ok_or_else(|| color_eyre::eyre::eyre!("Missing sha"))?
        .to_string();

    // GitLab MRs from forks have source_project_id different from target_project_id
    // We need to fetch the source project to get its clone URL
    let source_project_id = json
        .get("source_project_id")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| color_eyre::eyre::eyre!("Missing source_project_id"))?;

    let source_project_url = if pr_ref.host == "gitlab.com" {
        format!("https://gitlab.com/api/v4/projects/{}", source_project_id)
    } else {
        format!("https://{}/api/v4/projects/{}", pr_ref.host, source_project_id)
    };

    let source_response = client
        .get(&source_project_url)
        .header("User-Agent", "devaipod")
        .send()
        .await
        .context("Failed to fetch source project")?;

    let source_json: serde_json::Value = source_response.json().await?;
    let head_clone_url = source_json
        .get("http_url_to_repo")
        .and_then(|v| v.as_str())
        .ok_or_else(|| color_eyre::eyre::eyre!("Missing http_url_to_repo"))?
        .to_string();

    Ok(PullRequestInfo {
        pr_ref: pr_ref.clone(),
        title,
        head_clone_url,
        head_ref: source_branch,
        head_sha,
    })
}

/// Fetch Forgejo/Gitea PR metadata
async fn fetch_forgejo_pr(pr_ref: &PullRequestRef) -> Result<PullRequestInfo> {
    let api_url = format!(
        "https://{}/api/v1/repos/{}/{}/pulls/{}",
        pr_ref.host, pr_ref.owner, pr_ref.repo, pr_ref.number
    );

    let client = reqwest::Client::new();
    let mut request = client
        .get(&api_url)
        .header("User-Agent", "devaipod");

    // Use FORGEJO_TOKEN or GITEA_TOKEN if available
    if let Ok(token) = std::env::var("FORGEJO_TOKEN").or_else(|_| std::env::var("GITEA_TOKEN")) {
        request = request.header("Authorization", format!("token {}", token));
    }

    let response = request.send().await.context("Failed to fetch PR from Forgejo/Gitea API")?;

    if !response.status().is_success() {
        bail!(
            "Forgejo/Gitea API returned {}: {}",
            response.status(),
            response.text().await.unwrap_or_default()
        );
    }

    let json: serde_json::Value = response.json().await.context("Failed to parse Forgejo/Gitea API response")?;

    let title = json
        .get("title")
        .and_then(|v| v.as_str())
        .unwrap_or("Untitled")
        .to_string();

    let head = json.get("head").ok_or_else(|| color_eyre::eyre::eyre!("Missing 'head' in PR response"))?;

    let head_clone_url = head
        .get("repo")
        .and_then(|r| r.get("clone_url"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| color_eyre::eyre::eyre!("Missing head repo clone_url"))?
        .to_string();

    let head_ref = head
        .get("ref")
        .and_then(|v| v.as_str())
        .ok_or_else(|| color_eyre::eyre::eyre!("Missing head ref"))?
        .to_string();

    let head_sha = head
        .get("sha")
        .and_then(|v| v.as_str())
        .ok_or_else(|| color_eyre::eyre::eyre!("Missing head sha"))?
        .to_string();

    Ok(PullRequestInfo {
        pr_ref: pr_ref.clone(),
        title,
        head_clone_url,
        head_ref,
        head_sha,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_github_pr_url() {
        let pr = parse_pr_url("https://github.com/containers/composefs-rs/pull/200").unwrap();
        assert_eq!(pr.forge_type, ForgeType::GitHub);
        assert_eq!(pr.host, "github.com");
        assert_eq!(pr.owner, "containers");
        assert_eq!(pr.repo, "composefs-rs");
        assert_eq!(pr.number, 200);
    }

    #[test]
    fn test_parse_github_pr_url_trailing_slash() {
        let pr = parse_pr_url("https://github.com/owner/repo/pull/42/").unwrap();
        assert_eq!(pr.number, 42);
    }

    #[test]
    fn test_parse_gitlab_mr_url() {
        let pr = parse_pr_url("https://gitlab.com/owner/repo/-/merge_requests/123").unwrap();
        assert_eq!(pr.forge_type, ForgeType::GitLab);
        assert_eq!(pr.host, "gitlab.com");
        assert_eq!(pr.owner, "owner");
        assert_eq!(pr.repo, "repo");
        assert_eq!(pr.number, 123);
    }

    #[test]
    fn test_parse_forgejo_pr_url() {
        let pr = parse_pr_url("https://codeberg.org/owner/repo/pulls/456").unwrap();
        assert_eq!(pr.forge_type, ForgeType::Forgejo);
        assert_eq!(pr.host, "codeberg.org");
        assert_eq!(pr.owner, "owner");
        assert_eq!(pr.repo, "repo");
        assert_eq!(pr.number, 456);
    }

    #[test]
    fn test_parse_non_pr_url() {
        assert!(parse_pr_url("https://github.com/owner/repo").is_none());
        assert!(parse_pr_url("https://github.com/owner/repo/issues/123").is_none());
        assert!(parse_pr_url("not a url").is_none());
    }

    #[test]
    fn test_pr_ref_upstream_url() {
        let pr = PullRequestRef {
            forge_type: ForgeType::GitHub,
            host: "github.com".to_string(),
            owner: "containers".to_string(),
            repo: "composefs-rs".to_string(),
            number: 200,
        };
        assert_eq!(pr.upstream_url(), "https://github.com/containers/composefs-rs.git");
    }

    #[test]
    fn test_pr_ref_short_display() {
        let pr = PullRequestRef {
            forge_type: ForgeType::GitHub,
            host: "github.com".to_string(),
            owner: "containers".to_string(),
            repo: "composefs-rs".to_string(),
            number: 200,
        };
        assert_eq!(pr.short_display(), "containers/composefs-rs#200");
    }
}

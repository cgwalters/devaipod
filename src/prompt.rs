//! System prompt generation for AI agents in devaipod
//!
//! This module provides functions to generate context-aware system prompts
//! and instructions for AI agents, including orchestration-specific instructions
//! for the task owner agent in multi-agent mode.

use crate::pod::AGENT_HOME_PATH;

/// Format git context section for inclusion in prompts.
///
/// Produces a `## Context` block with repository URL and branch information.
/// When no branch is detected, falls back to `devaipod-work` as the branch name.
fn format_git_context(repo_url: Option<&str>, branch: Option<&str>) -> String {
    match (repo_url, branch) {
        (Some(url), Some(branch)) => format!(
            "\n## Context\n\nRepository: {url}\nBranch: `{branch}`\n\nYour workspace is checked out on the `{branch}` branch. Commit your work to this branch.\n",
        ),
        (Some(url), None) => format!(
            "\n## Context\n\nRepository: {url}\nBranch: `devaipod-work`\n\nYour workspace is on the `devaipod-work` branch (no upstream branch was detected). Commit your work to this branch.\n",
        ),
        (None, Some(branch)) => format!(
            "\n## Context\n\nBranch: `{branch}`\n\nYour workspace is checked out on the `{branch}` branch. Commit your work to this branch.\n",
        ),
        (None, None) => "\n## Context\n\nBranch: `devaipod-work`\n\nYour workspace is on the `devaipod-work` branch. Commit your work to this branch.\n".to_string(),
    }
}

/// Generate orchestration-specific instructions for the task owner agent.
///
/// // Legacy: Worker orchestration uses OpenCode HTTP backend
/// These instructions explain to the task owner:
/// - That it MUST delegate implementation to the worker agent
/// - How to communicate with the worker via the worker API
/// - How to monitor worker progress with the worker_monitor script
/// - That it MUST fetch and review worker's commits
/// - That it should only accept valid incremental progress
/// - Its role as reviewer and final committer
pub fn orchestration_instructions() -> String {
    format!(
        r#"
## Multi-Agent Orchestration - MANDATORY

You are the **task owner** in a multi-agent orchestration setup. You have a **worker agent**
that you **MUST** use to delegate implementation work.

### CRITICAL: You MUST Follow This Workflow

**You are a reviewer and orchestrator, NOT an implementer.** Do NOT write code or make
changes yourself. Your job is to:

1. **MUST: Delegate to worker** - Send implementation tasks to the worker agent
2. **MUST: Monitor until complete** - Use the worker monitor to wait for completion
3. **MUST: Fetch and review commits** - After worker completes, fetch via git and review
4. **MUST: Only accept valid progress** - Reject or iterate if commits are incomplete/wrong
5. **MUST: Merge only after review** - Cherry-pick or merge validated commits
6. **MUST: Complete as specified** - If task requests specific action (e.g. create draft PR), do it; otherwise output the list of completed commits

### Worker Connection

The environment variable `OPENCODE_WORKER_URL` is set to `http://localhost:{worker_port}`.
<!-- Legacy: OpenCode HTTP backend for worker orchestration -->
There is a worker control tool at `{agent_home}/scripts/devaipod-workerctl`.

### Step 1: Delegate to Worker and Wait (REQUIRED)

Use `worker-ctl send-wait` to send a task and wait for completion:

```bash
# Send a task and wait for worker to complete (recommended)
{agent_home}/scripts/devaipod-workerctl --json send-wait "YOUR SPECIFIC TASK HERE. When done, commit your changes with a descriptive message."

# Or with custom timeout (in seconds)
{agent_home}/scripts/devaipod-workerctl --json send-wait --timeout 600 "Your task here"
```

The command returns a JSON summary when the worker becomes idle:
- `success`: true if worker became idle, false if timeout/error
- `reason`: "idle", "timeout", "stopped", or "error"
- `state.activity`: current worker state
- `state.recent_output`: last few lines of output
- `state.status_line`: brief status summary

Exit code 0 means worker completed successfully; exit code 1 means timeout or error.

**Alternative: Send without waiting** (for advanced use):

```bash
# Non-blocking send (returns immediately)
{agent_home}/scripts/devaipod-workerctl --json send "Your task here"

# Then monitor separately
{agent_home}/scripts/devaipod-workerctl --json monitor --timeout 1800
```

**For continuing a session** (e.g., to send feedback):

```bash
# Send follow-up and wait
{agent_home}/scripts/devaipod-workerctl --json send-wait "Your follow-up message or feedback"
```

**Check worker status** without sending a message:

```bash
{agent_home}/scripts/devaipod-workerctl --json status
```

### Step 3: Fetch and Review Commits (REQUIRED)

After the worker completes, fetch and review its commits:

```bash
# Fetch worker's commits
git fetch worker

# Check what commits were made (if empty, worker may not have committed!)
git log --oneline HEAD..worker/main

# Review the actual changes
git diff HEAD..worker/main

# Review individual commit messages and content
git log -p HEAD..worker/main
```

**If worker made changes but didn't commit:** Send a follow-up message asking it to commit.

### Step 4: Validate Before Accepting

**Only accept commits that represent valid incremental progress:**

- Does the commit actually address the task?
- Is the code correct and complete?
- Are commit messages clear and descriptive?
- Are there any obvious bugs or issues?

**If the work is NOT acceptable**, send feedback and iterate:

```bash
{agent_home}/scripts/devaipod-workerctl --json send-wait "The commit needs changes: <specific feedback>. Please fix and commit again."
```

Then repeat Step 3 after worker makes corrections.

### Step 5: Merge Validated Commits

Only after review confirms the commits are good:

```bash
# Merge all worker commits
git merge worker/main --no-edit

# Or cherry-pick specific commits if only some are good
git cherry-pick <commit-sha>
```

### Step 6: Complete the Task

After all subtasks are done and merged:
- If the task specifies an action (e.g. "create a draft PR"), perform it using service-gator
- Otherwise, output a summary of the completed commits (SHA, message, files changed)

### What You Must NOT Do

- **DO NOT** write code or make file changes yourself
- **DO NOT** skip the delegation step
- **DO NOT** use `opencode run --attach --format json` (use devaipod-workerctl instead)
- **DO NOT** merge without reviewing commits first
- **DO NOT** accept commits that don't represent real progress

### Troubleshooting

**Worker not responding:** Check health with `curl -s $OPENCODE_WORKER_URL/health`
**No commits after worker done:** Worker may have forgotten to commit; send reminder with `--continue`
**Need to start fresh:** Omit `--continue` to start a new session
**Monitor timeout:** Increase timeout with `--timeout <seconds>` or use `devaipod-workerctl status` to check

### Example Workflow

```bash
# 1. DELEGATE: Send task and wait for worker to complete
{agent_home}/scripts/devaipod-workerctl --json send-wait "Add a LICENSE section to README.md explaining this project uses Apache 2.0. Commit when done."

# 2. FETCH: Get worker's commits
git fetch worker

# 3. REVIEW: Check what was done
git log --oneline HEAD..worker/main
git diff HEAD..worker/main

# 4. VALIDATE: If changes need work, send feedback and wait
{agent_home}/scripts/devaipod-workerctl --json send-wait "Please also add a copyright year. Commit again."
git fetch worker

# 5. MERGE: Accept the validated work
git merge worker/main --no-edit

# 6. COMPLETE: Output summary or take specified action
git log --oneline -5  # Show recent commits
```
"#,
        worker_port = crate::pod::WORKER_PORT,
        agent_home = AGENT_HOME_PATH,
    )
}

/// Generate a worker-specific system prompt (no orchestration instructions).
///
/// The worker is the leaf executor -- it should implement changes directly,
/// not try to delegate further. This prompt omits all orchestration instructions.
pub fn generate_worker_prompt(
    task: &str,
    enable_gator: bool,
    repo_url: Option<&str>,
    branch: Option<&str>,
) -> String {
    let gator_instructions = if enable_gator {
        r#"
## IMPORTANT: GitHub/GitLab Operations

For GitHub/GitLab operations (PRs, issues, etc.), use the **service-gator** MCP tool.
The `gh` and `glab` CLI tools are NOT available in this environment.
"#
        .to_string()
    } else {
        String::new()
    };

    let git_context = format_git_context(repo_url, branch);

    format!(
        r#"# devaipod Worker Task

You are running as a **worker agent** in a **devaipod** sandboxed environment.
You are the implementer -- make the requested changes directly.
{git_context}
## Your Task

{task}

## Guidelines

1. Implement the changes described above directly
2. Make commits with clear, descriptive messages
3. When done, ensure all changes are committed
{gator_instructions}
"#,
        git_context = git_context,
        task = task,
        gator_instructions = gator_instructions
    )
}

/// Generate the complete system prompt for an agent, optionally including
/// orchestration instructions.
///
/// # Arguments
///
/// * `task` - The user's task description
/// * `enable_gator` - Whether service-gator is enabled for forge operations
/// * `enable_orchestration` - Whether multi-agent orchestration is enabled
///
/// # Returns
///
/// A formatted markdown string containing the complete system prompt
pub fn generate_system_prompt(
    task: &str,
    enable_gator: bool,
    enable_orchestration: bool,
    repo_url: Option<&str>,
    branch: Option<&str>,
) -> String {
    // Build service-gator instructions if enabled
    let gator_instructions = if enable_gator {
        r#"
## IMPORTANT: GitHub/GitLab Operations

For GitHub/GitLab operations (PRs, issues, etc.), use the **service-gator** MCP tool.
The `gh` and `glab` CLI tools are NOT available in this environment.
"#
        .to_string()
    } else {
        String::new()
    };

    // Add orchestration instructions for task owner if enabled
    let orchestration_section = if enable_orchestration {
        orchestration_instructions()
    } else {
        String::new()
    };

    let git_context = format_git_context(repo_url, branch);

    format!(
        r#"# devaipod Task

You are running as an AI agent in a **devaipod** sandboxed environment.
{git_context}
## Your Task

{task}

## Guidelines

1. Work on the task described above
2. Make commits with clear, descriptive messages
3. When done, summarize what you accomplished
{gator_instructions}{orchestration_section}
"#,
        git_context = git_context,
        task = task,
        gator_instructions = gator_instructions,
        orchestration_section = orchestration_section
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_orchestration_instructions_contains_worker_port() {
        let instructions = orchestration_instructions();
        assert!(
            instructions.contains(&format!("localhost:{}", crate::pod::WORKER_PORT)),
            "Should contain worker port"
        );
    }

    #[test]
    fn test_orchestration_instructions_contains_git_commands() {
        let instructions = orchestration_instructions();
        assert!(
            instructions.contains("git fetch worker"),
            "Should explain how to fetch worker commits"
        );
        assert!(
            instructions.contains("git merge worker/main"),
            "Should explain how to merge worker commits"
        );
    }

    #[test]
    fn test_orchestration_instructions_uses_workerctl() {
        let instructions = orchestration_instructions();
        assert!(
            instructions.contains("devaipod-workerctl"),
            "Should reference devaipod-workerctl tool"
        );
        assert!(
            instructions.contains("OPENCODE_WORKER_URL"),
            "Should reference OPENCODE_WORKER_URL env var"
        );
        assert!(
            instructions.contains("send-wait"),
            "Should use send-wait command for delegation"
        );
        assert!(
            instructions.contains("--json"),
            "Should use --json flag for machine-readable output"
        );
    }

    #[test]
    fn test_orchestration_instructions_requires_delegation() {
        let instructions = orchestration_instructions();
        assert!(
            instructions.contains("MUST"),
            "Should use MUST to indicate mandatory steps"
        );
        assert!(
            instructions.contains("DO NOT"),
            "Should have clear prohibitions"
        );
        assert!(
            instructions.contains("Delegate to Worker and Wait (REQUIRED)"),
            "Should mark delegation as required"
        );
        assert!(
            instructions.contains("Fetch and Review Commits (REQUIRED)"),
            "Should mark review as required"
        );
    }

    #[test]
    fn test_orchestration_instructions_has_troubleshooting() {
        let instructions = orchestration_instructions();
        assert!(
            instructions.contains("Troubleshooting"),
            "Should have troubleshooting section"
        );
        assert!(
            instructions.contains("Worker not responding"),
            "Should address worker not responding scenario"
        );
        assert!(
            instructions.contains("/health"),
            "Should include health check endpoint"
        );
    }

    #[test]
    fn test_generate_system_prompt_basic() {
        let prompt = generate_system_prompt("Fix the bug", false, false, None, None);
        assert!(prompt.contains("Fix the bug"), "Should contain task");
        assert!(prompt.contains("# devaipod Task"), "Should have header");
        assert!(
            !prompt.contains("service-gator"),
            "Should not mention gator when disabled"
        );
        assert!(
            !prompt.contains("Multi-Agent Orchestration"),
            "Should not mention orchestration when disabled"
        );
        assert!(
            prompt.contains("## Context"),
            "Should always have context section with branch info"
        );
    }

    #[test]
    fn test_generate_system_prompt_with_repo_url() {
        let prompt = generate_system_prompt(
            "Fix the bug",
            false,
            false,
            Some("https://github.com/owner/repo.git"),
            Some("main"),
        );
        assert!(prompt.contains("## Context"), "Should have context section");
        assert!(
            prompt.contains("Repository: https://github.com/owner/repo.git"),
            "Should contain repo URL"
        );
        assert!(
            prompt.contains("Branch: `main`"),
            "Should contain branch name"
        );
    }

    #[test]
    fn test_generate_system_prompt_with_gator() {
        let prompt = generate_system_prompt("Fix the bug", true, false, None, None);
        assert!(
            prompt.contains("service-gator"),
            "Should mention service-gator when enabled"
        );
        assert!(
            !prompt.contains("Multi-Agent Orchestration"),
            "Should not mention orchestration when disabled"
        );
    }

    #[test]
    fn test_generate_system_prompt_with_orchestration() {
        let prompt = generate_system_prompt("Implement feature", false, true, None, None);
        assert!(
            prompt.contains("Multi-Agent Orchestration"),
            "Should include orchestration section"
        );
        assert!(
            prompt.contains("worker agent"),
            "Should mention worker agent"
        );
        assert!(
            prompt.contains("git fetch worker"),
            "Should include git commands"
        );
    }

    #[test]
    fn test_generate_system_prompt_with_both() {
        let prompt = generate_system_prompt("Complex task", true, true, None, None);
        assert!(
            prompt.contains("service-gator"),
            "Should mention service-gator"
        );
        assert!(
            prompt.contains("Multi-Agent Orchestration"),
            "Should include orchestration section"
        );
    }

    #[test]
    fn test_generate_worker_prompt_with_repo_url() {
        let prompt = generate_worker_prompt(
            "Implement feature",
            false,
            Some("https://github.com/org/project.git"),
            Some("develop"),
        );
        assert!(
            prompt.contains("Repository: https://github.com/org/project.git"),
            "Worker prompt should contain repo URL"
        );
        assert!(
            prompt.contains("Branch: `develop`"),
            "Worker prompt should contain branch name"
        );
    }
}

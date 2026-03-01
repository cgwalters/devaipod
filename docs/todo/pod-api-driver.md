# Pod-API as Driver: Move Agent Lifecycle into the Sidecar

## Problem

Today the control plane orchestrates the agent lifecycle with a fragile,
racy multi-step sequence:

1. `write_task()` injects the task as a global opencode `instructions` file
   **and** mutates `opencode.json` via `podman exec` into the agent container.
2. A state-file gate (`/var/lib/devaipod-state.json`) holds the agent
   container's entrypoint until the config is written.
3. `start_agent_task()` then polls the opencode server (via `podman exec curl`
   into the *workspace* container) until healthy, creates a session, and sends
   the task as the first message — duplicating the instructions already in
   the config.
4. `agent-status` on the web side goes control-plane → pod-api → opencode,
   but the session was created by code that bypassed pod-api entirely.

Issues:

- **Race**: The config-file write and session creation compete with opencode
  startup and dotfiles installation; timing matters.
- **Duplication**: The task appears both as a global `instructions` entry
  (every session gets it) and as the first user message.
- **Coupling**: The control plane reaches past pod-api via `podman exec`
  for session creation and health checks, creating two separate paths to
  the same opencode instance.
- **Global mutation**: Writing the task into `opencode.json` `instructions`
  means *every* future session in that pod inherits the original task prompt,
  which is wrong for interactive use or re-tasking.

## Goal

Pod-api becomes the single entry point for all agent lifecycle operations.
The control plane never talks directly to opencode; it talks to pod-api,
which owns the relationship with the opencode server running beside it in
the same pod network namespace.

Key changes:

1. Opencode starts idle — no task in `instructions`, no session pre-created.
   It still waits for dotfiles to finish (existing state-file gate is fine).
2. The control plane passes the task to pod-api via a new endpoint.
3. Pod-api polls opencode until ready, then creates a session with the task
   as the initial user message.
4. Pod-api becomes the source of truth for pod/agent status; the control
   plane queries pod-api instead of reimplementing status derivation.

## Design

### New pod-api endpoints

**`POST /task`** — accept the task from the control plane.

```json
{
  "task": "Fix the flaky CI test in src/integration.rs",
  "enable_gator": true,
  "enable_orchestration": false,
  "repo_url": "https://github.com/example/repo"
}
```

Pod-api stores this in memory. It then:

1. Polls `GET http://127.0.0.1:4096/session` until opencode responds (with
   backoff, same retry logic already in `proxy_to_opencode()`).
2. Generates the system prompt via `generate_system_prompt()` (the prompt
   module is already compiled into the same binary).
3. `POST /session` to opencode to create a new session.
4. `POST /session/{id}/message` with the generated prompt + task as the
   user message body.

This replaces `start_agent_task()` and `send_initial_message()` in main.rs.

**`GET /status`** — return structured agent status.

```json
{
  "state": "working",
  "session_id": "abc123",
  "current_tool": "bash",
  "status_line": "Running tests...",
  "opencode_ready": true
}
```

Pod-api already has access to everything needed (it proxies to opencode).
Move the `derive_agent_status_from_messages()` logic from `web.rs` into
pod-api so the control plane gets a pre-computed status rather than
fetching raw sessions/messages and deriving status itself.

### What stays the same

- **`opencode.json` config**: Still written by the control plane during pod
  creation for settings that genuinely belong in the global config: `snapshot:
  false`, any provider/model overrides, MCP server config, etc. The key
  change is that `instructions` no longer contains the task — it only has
  repo-level AGENTS.md or similar permanent context, if any.
- **Dotfiles / state-file gate**: The agent container still waits for
  dotfiles before starting opencode. Pod-api just polls until opencode is
  actually responding.
- **Git, PTY, opencode proxy endpoints**: Unchanged.
- **Pod creation flow**: The control plane still creates containers, clones
  repos, installs dotfiles. It just stops short of creating a session or
  injecting the task into config.

### Control plane changes

- `write_task()` — remove the instructions-injection and opencode.json
  mutation for the task file. Keep the config write for `snapshot: false`
  and other non-task settings.
- `start_agent_task()` / `send_initial_message()` — replace with a single
  `POST /task` call to pod-api (via the existing `proxy_to_upstream()` or
  direct reqwest call to the pod-api published port).
- `agent_status()` in web.rs — replace the session-fetching and
  `derive_agent_status_from_messages()` logic with a single
  `GET /status` call to pod-api. The control plane becomes a thin proxy.
- Remove `check_agent_health()` (the `podman exec nc -z` approach); pod-api
  handles readiness internally.
- Remove `opencode_api_get()` / `opencode_api_post()` (the `podman exec
  curl` helpers) — these are no longer needed once all interaction goes
  through pod-api.

## Migration / ordering

### Phase 1: `POST /task` endpoint on pod-api

Add the endpoint. Pod-api receives the task, polls opencode, creates a
session, sends the message. Control plane calls this instead of doing
the `podman exec` dance.

Keep `write_task()` for now but stop adding the task to `instructions` —
only write the non-task parts of opencode.json.

### Phase 2: `GET /summary` endpoint on pod-api — DONE

Implemented as `GET /summary` (named "summary" rather than "status" to
avoid confusion with HTTP status codes and to reflect that it returns a
richer pod-level summary). `derive_agent_status_from_messages()` now
lives in `pod_api.rs` and the control plane's `agent_status()` is a
thin proxy to `/summary`.

### Phase 3: Remove dead code

Delete `start_agent_task()`, `send_initial_message()`, `check_agent_health()`,
`opencode_api_get()`, `opencode_api_post()`, and the workspace-monitor
Python script remnants. Remove the task-file-in-instructions path from
`write_task()`.

## Open questions

- **Re-tasking**: Should `POST /task` be idempotent (create a new session
  each time) or reject if a session already exists? Probably create a new
  session — this supports the "send another task to a running pod" use case.
- **Orchestration**: Worker pods also need tasks. The orchestration flow
  likely needs the same treatment (worker pod-api creates its own session).
  Defer to a follow-up.
- **Instructions file**: Some permanent per-repo context (AGENTS.md path,
  contribution guidelines) still belongs in opencode `instructions`. The
  task itself does not. We might want pod-api to also handle writing the
  instructions config, but that's separable.

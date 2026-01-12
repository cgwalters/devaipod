# Future: Interactive Upcalls via XDG Desktop Portal and ACP

This document explores extending devaipod's upcall mechanism to support
interactive permission prompts, inspired by
[XDG Desktop Portal](https://flatpak.github.io/xdg-desktop-portal/docs/) and the
[Agent Client Protocol (ACP)](https://agentclientprotocol.org/).

## Background

Both devaipod upcalls and XDG Desktop Portal solve the same fundamental problem:
allowing sandboxed applications to perform privileged operations in a controlled way.

| Aspect | devaipod Upcalls | XDG Desktop Portal |
|--------|------------------|-------------------|
| Transport | Unix socket + JSON-RPC 2.0 | D-Bus |
| Socket/bus | `/run/devaipod.sock` | Session bus (`org.freedesktop.portal.Desktop`) |
| Operations | `exec`, `get_state`, `add_pr` | FileChooser, Screenshot, Access, etc. |
| Interactive UI | None currently | Dialogs via `Request` object + `Response` signal |
| Permission model | Allowlist-based (binaries in `/usr/lib/devaipod/upcalls/`) | App-id based + user consent dialogs |

## The Request Pattern

XDG Desktop Portal uses an asynchronous request/response pattern for interactive operations:

1. App calls a portal method
2. Portal returns a `Request` object path immediately
3. Desktop shows a dialog to the user
4. When user responds, portal emits `Response` signal with the result

This pattern could be adapted for devaipod to enable human-in-the-loop approval
for sensitive agent operations.

## Current Blocked Operations

These operations are currently blocked in `gh-restricted` because they require
human judgment:

| Operation | Why Blocked | Interactive Alternative |
|-----------|-------------|------------------------|
| `gh pr ready` | Marking PR ready is a human decision | Prompt: "Mark PR #123 as ready for review?" |
| `gh pr merge` | Merging requires human approval | Prompt: "Merge PR #123 into main?" with options |
| `gh pr close` | Closing is a human decision | Prompt: "Close PR #123?" |
| Write to new repo | Security boundary | Prompt: "Allow agent to create PRs in owner/newrepo?" |

## Proposed Design

### New RPC Method: `request_permission`

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "request_permission",
  "params": {
    "operation": "pr_ready",
    "title": "Mark PR as Ready",
    "description": "PR #123: Fix sandboxing documentation",
    "details": {
      "repo": "cgwalters/devaipod",
      "pr_number": 123,
      "pr_url": "https://github.com/cgwalters/devaipod/pull/123"
    },
    "choices": [
      {
        "id": "notify_reviewers",
        "label": "Notify reviewers",
        "default": true
      }
    ]
  }
}
```

### Response Flow

1. Agent calls `request_permission`
2. devaipod returns a pending request ID
3. devaipod presents the request to the human (terminal UI, desktop notification, or portal dialog)
4. Human approves or denies
5. Agent receives response via follow-up RPC or callback

### Presentation Options

The permission request could be presented via:

1. **Terminal UI** - Simple prompt in the devaipod session
2. **Desktop notification** - Non-blocking, with action buttons
3. **XDG Access portal** - Full desktop dialog via `org.freedesktop.impl.portal.Access`
4. **Agent-native prompts** - Some AI agents (like Claude/Anthropic's MCP) have built-in permission UIs

## Agent Client Protocol (ACP)

The [Agent Client Protocol](https://agentclientprotocol.org/) is particularly
relevant as it already defines a standardized permission request mechanism that
coding agents can use. ACP is designed for communication between code editors/IDEs
and coding agents (developed by Zed Industries and JetBrains).

### ACP's `session/request_permission` Method

ACP defines a [`session/request_permission`](https://agentclientprotocol.org/protocol/tool-calls#requesting-permission)
method that agents use to request user approval before executing sensitive tool calls:

```json
{
  "jsonrpc": "2.0",
  "id": 5,
  "method": "session/request_permission",
  "params": {
    "sessionId": "sess_abc123def456",
    "toolCall": {
      "toolCallId": "call_001",
      "title": "Merge pull request",
      "kind": "execute",
      "status": "pending"
    },
    "options": [
      {
        "optionId": "allow-once",
        "name": "Allow once",
        "kind": "allow_once"
      },
      {
        "optionId": "allow-always",
        "name": "Always allow",
        "kind": "allow_always"
      },
      {
        "optionId": "reject-once",
        "name": "Reject",
        "kind": "reject_once"
      }
    ]
  }
}
```

The client responds with the user's decision:

```json
{
  "jsonrpc": "2.0",
  "id": 5,
  "result": {
    "outcome": {
      "outcome": "selected",
      "optionId": "allow-once"
    }
  }
}
```

### ACP Session Modes

ACP also defines [session modes](https://agentclientprotocol.org/protocol/session-modes)
that affect whether agents request permission:

- **"Ask" mode**: Request permission before making any changes
- **"Architect" mode**: Design and plan without implementation
- **"Code" mode**: Write and modify code with full tool access

This maps well to devaipod's needs - an agent could operate in "ask" mode for
sensitive GitHub operations while having unrestricted access for file operations
within the sandbox.

### Bridging devaipod Upcalls to ACP

When devaipod hosts an ACP-compatible agent, upcalls requiring approval could
potentially be bridged to the agent's permission UI:

```
Agent (via ACP) → calls tool "gh pr merge"
       ↓
devaipod's gh-restricted intercepts
       ↓
gh-restricted calls upcall: request_permission
       ↓
devaipod upcall listener detects ACP session
       ↓
Forwards to ACP client via session/request_permission
       ↓
User sees permission dialog in their editor (Zed, JetBrains, etc.)
       ↓
Response flows back through the chain
```

**However, this has a fundamental security limitation** - see
[The Fundamental Trust Problem](#the-fundamental-trust-problem) below. If the
ACP client displaying the permission UI runs inside the sandbox (or is controlled
by code inside the sandbox), the security guarantee is weakened.

This approach may still be useful for **usability** (consistent UI, editor
integration) when the threat model accepts that the agent could potentially
bypass the permission check. For stronger security, devaipod needs its own
trusted UI running outside the sandbox.

## Bridging to Other Agent Permission Systems

For agents not using ACP, devaipod could fall back to other mechanisms:

```
Agent → "I want to merge PR #123"
       ↓
devaipod receives request
       ↓
If agent uses ACP:
  → Forward via session/request_permission
Else if XDG portal available:
  → Show desktop dialog via Access portal
Else:
  → Terminal prompt or block the operation
```

## Relevant XDG Portal Interfaces

| Portal | Relevance | Use Case |
|--------|-----------|----------|
| **Access** (impl) | High | Generic grant/deny dialogs |
| **Notification** | Medium | Inform user of completed actions |
| **Secret** | Medium | Secure credential retrieval |

The `org.freedesktop.impl.portal.Access.AccessDialog` method is particularly
relevant - it presents a "deny/grant" question with customizable title, subtitle,
body text, and optional choices.

## Implementation Steps

### Phase 1: Define the protocol

- Add `request_permission` and `check_permission_status` RPC methods
- Define permission request/response structures
- Add request queue and state tracking

### Phase 2: Terminal UI

- Implement a simple terminal-based approval flow
- Could use the existing devaipod session or a separate approval channel

### Phase 3: Desktop integration

- Implement as an XDG portal backend
- Or use `notify-send` with action callbacks as a simpler alternative

### Phase 4: Agent framework bridges

- Detect when running under agent frameworks with native permission UIs
- Forward requests to the agent's permission system when available

## Security Considerations

### The Fundamental Trust Problem

A critical architectural issue: **the permission UI must run outside the sandbox
to provide real security guarantees.**

If the agent running inside the sandbox could directly control or influence the
permission UI, it could potentially:

- Manipulate the displayed information to mislead the user
- Auto-approve its own requests
- Suppress or modify the permission prompt

This is why XDG Desktop Portal works the way it does - the portal frontend runs
as a separate, trusted process outside the sandboxed application.

### Why Bridging to In-Agent UIs Is Insufficient

Consider the ACP bridge approach described above:

```
Agent (sandboxed) → upcall → devaipod → ACP client → permission UI
```

If the "ACP client" showing the permission dialog is part of the same agent
process running inside the sandbox, the security boundary is compromised. The
agent could potentially intercept or forge the permission response.

For true security, the architecture must be:

```
Agent (sandboxed) → upcall socket → devaipod (outside sandbox) → UI (outside sandbox)
                                                                      ↓
                                                              Human sees trusted UI
```

### Implications for devaipod

To support interactive permissions securely, devaipod would need to implement
its own trusted UI layer running outside the sandbox. Options include:

1. **devaipod terminal UI** - The existing devaipod process (which runs the
   upcall listener outside the sandbox) could prompt in its own terminal session

2. **Separate approval daemon** - A dedicated process that displays permission
   requests, similar to how `polkit` agents work

3. **XDG portal integration** - Use the desktop's existing trusted portal
   frontend (requires D-Bus access and desktop session)

4. **Web UI** - devaipod could serve a local web interface for approvals
   (requires ensuring the agent can't access it)

The key insight is that we cannot simply forward permission requests back into
the sandboxed agent's UI and expect security - the approval mechanism must be
controlled by code the agent cannot influence.

### Other Security Considerations

- Requests should include enough context for informed decisions
- Rate limiting to prevent prompt fatigue attacks
- Timeouts for pending requests
- Audit logging of all permission decisions
- Consider "remember this decision" options with appropriate scoping
- Permission state must be stored outside the sandbox

## References

### Agent Client Protocol (ACP)

- [ACP Introduction](https://agentclientprotocol.org/overview/introduction)
- [ACP Tool Calls & Permission Requests](https://agentclientprotocol.org/protocol/tool-calls)
- [ACP Session Modes](https://agentclientprotocol.org/protocol/session-modes)
- [ACP GitHub Repository](https://github.com/agentclientprotocol/agent-client-protocol)

### XDG Desktop Portal

- [XDG Desktop Portal Documentation](https://flatpak.github.io/xdg-desktop-portal/docs/)
- [Portal Request Pattern](https://flatpak.github.io/xdg-desktop-portal/docs/requests.html)
- [Access Portal Backend Interface](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.impl.portal.Access.html)

# Web UI Integration Testing

🤖 Assisted-by: Opus 4.6

The following text is 100% LLM generated (after research).

---

End-to-end testing of the devaipod web UI against real containers.
All tests described here involve actual podman pods with workspace,
agent, and pod-api containers. There are no mocked git endpoints or
fake container orchestration.

## Motivation

The existing integration tests (`crates/integration-tests/`) validate
container structure, volume mounts, pod lifecycle, and HTTP endpoint
responses, but never open a browser. The vendored opencode-ui has 33
Playwright spec files from upstream, but they test upstream opencode
features (sessions, prompts, settings) against a standalone opencode
server, not the devaipod pod-api sidecar.

The devaipod-specific UI components -- `GitReviewTab`, the gator scope
dialog, the pod management sidebar -- have zero browser test coverage.
The git review flow in particular (agent commits → human reviews diffs
→ approve → push) is the critical path that needs E2E validation.

## Architecture

```
┌─ Playwright (Chromium) ─────────────────────────────┐
│                                                      │
│  Navigates to pod-api's web server                   │
│  Interacts with GitReviewTab, push button, etc.      │
│                                                      │
└──────────────┬───────────────────────────────────────┘
               │ HTTP
               ▼
┌─ Pod-api sidecar ───────────────────────────────────┐
│  Serves vendored opencode UI (static SPA)            │
│  Proxies opencode API to mock-opencode in agent      │
│  Serves /git/log, /git/diff-range, /git/events       │
│  Serves /devaipod/context, /gator/scopes             │
└──────────────┬───────────────────────────────────────┘
               │ volume mounts
        ┌──────┴──────┐
        ▼             ▼
  agent workspace   main workspace
  (commits made     (push target,
   via podman exec)  workspace agent)
```

The test harness creates a real pod, execs `git commit` into the agent
container to simulate agent work, then drives a Chromium browser via
Playwright against the pod-api's HTTP server. No LLM is involved; the
mock-opencode keeps the `/summary` endpoint happy while we test git
review mechanics.

## Prerequisites

### Container image: `integration-web-runner`

A new Containerfile stage based on the official Playwright image,
with the devaipod binary and a small TypeScript test harness copied
in. This keeps the existing `integration-runner` lean (no Chromium)
while getting a known-good browser environment from Microsoft.

```dockerfile
# New Containerfile stage
FROM mcr.microsoft.com/playwright:v1.57.0-noble AS integration-web-runner

# podman-remote for pod lifecycle (same pattern as integration-runner)
RUN apt-get update && apt-get install -y podman-remote \
    && ln -sf /usr/bin/podman-remote /usr/bin/podman \
    && apt-get clean

# The devaipod binary (for pod creation/teardown)
COPY --from=build /usr/bin/devaipod /usr/bin/devaipod

# Playwright test harness (TypeScript tests + config)
COPY e2e-devaipod/ /opt/e2e-devaipod/
WORKDIR /opt/e2e-devaipod
RUN npm ci

ENV DEVAIPOD_CONTAINER=1
ENV CONTAINER_HOST=unix:///run/docker.sock

CMD ["npx", "playwright", "test"]
```

The Playwright image already has Chromium, Firefox, and WebKit
installed. The `e2e-devaipod/` directory is a new top-level directory
(not inside `opencode-ui/`) containing devaipod-specific Playwright
tests, a separate `playwright.config.ts`, and a `package.json` that
depends only on `@playwright/test`.

### Architecture: Rust orchestrates, Playwright tests

The Rust integration test binary remains the orchestrator for pod
lifecycle. A new Rust test function creates pods, waits for health,
then spawns `npx playwright test` as a subprocess with env vars:

```
┌─ integration-web-runner container ──────────────────┐
│                                                      │
│  devaipod binary                                     │
│    └─ starts web server on random port               │
│    └─ creates pods (talks to host podman via socket)  │
│                                                      │
│  npx playwright test                                 │
│    └─ reads DEVAIPOD_BASE_URL, DEVAIPOD_TOKEN        │
│    └─ launches Chromium                              │
│    └─ navigates to control plane                     │
│    └─ interacts with pod switcher, git review, etc.  │
│                                                      │
└──────────────┬───────────────────────────────────────┘
               │ podman socket
               ▼
         host podman
```

The key difference from the existing integration tests: instead of
verifying HTML strings via raw HTTP, Playwright opens a real browser
and interacts with the rendered DOM.

### Control plane proxy (no port publishing needed)

Playwright navigates to the control plane URL
(`http://localhost:<port>/`) which proxies to pod-api sidecars. This
tests the real production path. No need to publish pod-api ports
directly.

### Auth token injection

The devaipod login endpoint (`/_devaipod/login?token=...`) sets an
HttpOnly cookie. Playwright navigates to this URL first, which sets
the cookie, then navigates to the agent iframe. Alternatively, use
`page.addInitScript()` to inject the token into `sessionStorage`
(matching the pattern in `opencode-ui/packages/app/e2e/fixtures.ts`).

## Test Fixture Design

### File layout

```
e2e-devaipod/                     # New top-level directory
├── package.json                  # { "@playwright/test": "1.57.0" }
├── playwright.config.ts          # Chromium only, reads env vars
├── fixtures.ts                   # DevaipodFixture (auth, navigation)
├── pod-switcher.spec.ts          # Pod switcher tests
├── git-review.spec.ts            # Git review tab tests (future)
└── tsconfig.json
```

This is separate from `opencode-ui/packages/app/e2e/` which tests
the upstream opencode SPA. The `e2e-devaipod/` tests target the
devaipod control plane and agent iframe wrapper.

### Playwright config

```typescript
// e2e-devaipod/playwright.config.ts
import { defineConfig, devices } from "@playwright/test"

export default defineConfig({
  testDir: ".",
  timeout: 60_000,
  expect: { timeout: 10_000 },
  retries: process.env.CI ? 2 : 0,
  reporter: [["html", { open: "never" }], ["line"]],
  use: {
    baseURL: process.env.DEVAIPOD_BASE_URL || "http://localhost:8080",
    trace: "on-first-retry",
    screenshot: "only-on-failure",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
})
```

### `DevaipodFixture`

```typescript
// e2e-devaipod/fixtures.ts
import { test as base, expect, Page } from "@playwright/test"

type DevaipodFixture = {
  baseUrl: string
  token: string
  // Navigate to the login endpoint, setting the auth cookie
  login: (page: Page) => Promise<void>
  // Navigate to a specific pod's agent iframe
  gotoAgent: (page: Page, podShortName: string) => Promise<void>
  // Fetch the pod list from the API
  getPods: () => Promise<Array<{ name: string; status: string }>>
}

export const test = base.extend<DevaipodFixture>({
  baseUrl: async ({}, use) => {
    await use(process.env.DEVAIPOD_BASE_URL || "http://localhost:8080")
  },
  token: async ({}, use) => {
    const token = process.env.DEVAIPOD_TOKEN
    if (!token) throw new Error("DEVAIPOD_TOKEN not set")
    await use(token)
  },
  login: async ({ baseUrl, token }, use) => {
    await use(async (page) => {
      await page.goto(`${baseUrl}/_devaipod/login?token=${token}`)
      // Login redirects to /pods; cookie is now set
    })
  },
  gotoAgent: async ({ baseUrl, token }, use) => {
    await use(async (page, podShortName) => {
      // Login first to set cookie
      await page.goto(`${baseUrl}/_devaipod/login?token=${token}`)
      await page.goto(`${baseUrl}/_devaipod/agent/${podShortName}/`)
      await page.waitForSelector("#dbar")
    })
  },
  getPods: async ({ baseUrl, token }, use) => {
    await use(async () => {
      const resp = await fetch(`${baseUrl}/api/devaipod/pods`, {
        headers: { Authorization: `Bearer ${token}` },
      })
      return resp.json()
    })
  },
})

export { expect }
```

### Bridging: Playwright `globalSetup` orchestrates pods

Rather than Rust spawning Playwright as a subprocess, the Playwright
`globalSetup` script handles everything. The `devaipod` binary is
available in the container image:

```typescript
// e2e-devaipod/global-setup.ts
import { execSync } from "child_process"

export default async function globalSetup() {
  // Start devaipod web server
  // Create test pods via CLI
  // Store base URL and token in process.env for fixtures
  // Pod cleanup happens in globalTeardown
}
```

This is simpler than the Rust-subprocess approach because:
- No need for the Rust integration test binary in the web runner image
- Playwright controls the full lifecycle
- The `devaipod` binary handles pod creation robustly
- Cleanup is straightforward in `globalTeardown`

The tradeoff is some duplication of setup logic vs the Rust harness,
but TypeScript is the natural language for Playwright tests.

## Test Scenarios

### 1. GitReviewTab renders agent commits

**Precondition**: Pod created, agent container has 2-3 commits with
file changes across multiple files.

```
1. Navigate to pod's web UI (via control plane proxy or pod-api port)
2. Assert: GitReviewTab is visible (devaipod context detected)
3. Assert: commit log shows all agent commits with correct messages
4. Select a base commit from the dropdown
5. Assert: diff view updates to show changes in the selected range
6. Expand a file diff
7. Assert: before/after content is correct
```

### 2. SSE auto-refresh on new agent commit

```
1. Navigate to review tab, note current commit count
2. Exec a new commit into the agent container
3. Assert (within 5s): commit log auto-refreshes, new commit appears
   (no manual page reload)
```

### 3. Viewed-files tracking gates push button

**Precondition**: Agent has made changes to 3+ files. Push button
and viewed-files tracking are implemented.

```
1. Navigate to review tab
2. Assert: "Approve & Push" button is disabled
3. Expand and scroll through file 1
4. Assert: file 1 is marked as viewed, button still disabled
5. View remaining files
6. Assert: button becomes enabled
```

### 4. Full push flow

**Precondition**: Workspace agent is implemented, pod has a test
upstream (bare git repo). This test needs its own pod (mutates state).

```
1. Agent container makes commits on a feature branch
2. Navigate to review tab, view all files
3. Click "Approve & Push"
4. Assert: push succeeds (UI shows success state)
5. Verify via podman exec: bare upstream repo has the commits
6. Optionally: check Signed-off-by if checkbox was checked
```

### 5. Inline comment routes to agent

```
1. Navigate to review tab, expand a file diff
2. Click on a line to add an inline comment
3. Type a comment and submit
4. Assert: comment is sent to the agent session
   (verify via opencode API or agent container state)
```

### 6. Base commit selector

```
1. Agent has 5+ commits
2. Navigate to review tab
3. Select different base commits from the dropdown
4. Assert: diff view updates correctly for each selection
5. Assert: file count and diff content change appropriately
```

### 7. Pod switcher dropdown with multiple pods (Playwright)

**Precondition**: Two pods created and Running, pod-api sidecars
healthy. Both pods visible in `/api/devaipod/pods`.

```
1. Navigate to pod A's agent iframe via control plane proxy
2. Assert: #pod-switcher is visible in the top bar
3. Click #pod-trigger to open the dropdown
4. Assert: dropdown is visible, contains entries for both pod A and pod B
5. Assert: pod A is highlighted as current (has .current class)
6. Assert: both entries show status dots (green/blue/purple)
7. Click pod B's entry in the dropdown
8. Assert: browser navigates to /_devaipod/agent/<pod-b-name>/
9. Assert: #pod-trigger now shows pod B's name or title
10. Click the right arrow (#next-pod) -- should be disabled (last pod)
11. Click the left arrow (#prev-pod) -- should navigate back to pod A
12. Assert: browser navigates to /_devaipod/agent/<pod-a-name>/
```

This is the primary pod switcher test. It validates the full
interactive flow: dropdown rendering, pod selection, and arrow
navigation between pods.

**Current coverage**: The server-side HTML/JS generation and API
responses are validated by `test_harness_pod_switcher_multi_pod` in
`controlplane.rs` (Rust, no browser). The Playwright test above
would replace/supplement that by testing the actual rendered DOM
interactions.

### 8. Pod switcher shows session title (Playwright)

**Precondition**: One pod Running with a session title set via
`/agent-status`.

```
1. Navigate to pod's agent iframe
2. Assert: #pod-trigger initially shows the pod short name
3. Wait for fetchTitle() to complete (polls /agent-status)
4. Assert: #pod-trigger text updates to the session title
5. Assert: document.title contains the session title
```

### 9. Pod switcher with single pod (Playwright)

**Precondition**: Only one pod Running.

```
1. Navigate to the pod's agent iframe
2. Click #pod-trigger to open dropdown
3. Assert: dropdown shows one entry, highlighted as current
4. Assert: both arrow buttons (#prev-pod, #next-pod) are disabled
5. Click the current entry -- no navigation (stays on same page)
```

### 10. Pod switcher HTML structure (Rust, no browser)

The Rust integration tests validate the server-side contract that
Playwright tests depend on:

- `test_harness_pod_switcher_multi_pod` (`controlplane.rs`): Creates
  two pods, verifies both appear as Running in the API, and checks
  that each pod's iframe wrapper HTML contains the expected DOM
  element IDs and JS function names.
- `test_web_agent_iframe_has_pod_switcher` (`webui.rs`): Same
  HTML structure checks running inside the container test
  infrastructure.

## Frontend Prerequisites

Before these tests can run, the `GitReviewTab` component needs
`data-component` and `data-action` attributes for Playwright
selectors. The upstream opencode convention is to use these attributes
exclusively (never CSS classes or IDs). Needed attributes:

- `data-component="git-review-tab"` on the review tab container
- `data-component="git-commit-log"` on the commit list
- `data-component="git-commit-item"` on individual commits
- `data-component="git-base-selector"` on the base commit dropdown
- `data-component="git-file-diff"` on each file diff section
- `data-action="approve-push"` on the push button
- `data-action="signoff-checkbox"` on the Signed-off-by toggle
- `data-slot="diff-before"` / `data-slot="diff-after"` on diff panels

The pod switcher component uses `id` attributes (already implemented):

- `id="pod-switcher"` on the switcher container
- `id="pod-trigger"` on the trigger button
- `id="prev-pod"` and `id="next-pod"` on arrow buttons
- `id="pod-dropdown"` on the dropdown container

## CI Integration

### Containerfile stage

Add `integration-web-runner` as a new target in the Containerfile:

```dockerfile
FROM mcr.microsoft.com/playwright:v1.57.0-noble AS integration-web-runner

RUN apt-get update && apt-get install -y podman-remote git \
    && ln -sf /usr/bin/podman-remote /usr/bin/podman \
    && apt-get clean

COPY --from=build /usr/bin/devaipod /usr/bin/devaipod
COPY e2e-devaipod/ /opt/e2e-devaipod/
WORKDIR /opt/e2e-devaipod
RUN npm ci

ENV DEVAIPOD_CONTAINER=1
ENV CONTAINER_HOST=unix:///run/docker.sock

CMD ["npx", "playwright", "test"]
```

### Justfile targets

```just
# Build the web integration test runner image
build-integration-web: container-build
    podman build --target integration-web-runner \
        -t localhost/devaipod-integration-web:latest .

# Run Playwright-based web integration tests in a container
test-integration-web: build-integration-web
    podman run --rm --privileged \
        --name devaipod-integration-web \
        -v {{podman_socket}}:/run/docker.sock \
        -v /tmp:/tmp:shared \
        -e DEVAIPOD_HOST_SOCKET={{podman_socket}} \
        -e DEVAIPOD_CONTAINER_IMAGE=localhost/devaipod:latest \
        -e DEVAIPOD_INSTANCE=integration-test \
        -e DEVAIPOD_MOCK_AGENT=1 \
        localhost/devaipod-integration-web:latest
```

This mirrors the existing `test-integration` target structure.
The `--privileged` flag and socket mount are the same as the
existing integration runner.

### GitHub Actions

```yaml
- name: Web integration tests (Playwright)
  run: just test-integration-web
  timeout-minutes: 15
```

Runs after `test-integration` in the CI pipeline. The
`container-build` step is shared (cached) between both jobs.

### Performance budget

Target: under 3 minutes total. Pod creation is ~10-15s per pod.
The `globalSetup` creates 2 pods (one shared for read-only tests,
one for mutating tests like push). Playwright tests should be
<5s each since the backend is already running.

## Relationship to Existing Tests

This complements, not replaces, the existing test infrastructure:

- **Unit tests** (`cargo test`): Pure logic, no containers. Sub-second.
- **Integration tests** (`just test-integration`): Container structure,
  volume mounts, HTTP endpoints, SSH -- verified via Rust HTTP client
  and `podman exec`. No browser. Includes pod switcher HTML structure
  checks (`test_harness_pod_switcher_multi_pod`).
- **Web integration tests** (`just test-integration-web`, this doc):
  Playwright in Chromium against real containers. Validates interactive
  UI behavior (dropdown clicks, navigation, status updates). New
  `integration-web-runner` container image.
- **E2E GitHub tests** (`just test-e2e-gh`): Real GitHub API
  operations (draft PRs, etc.). Slowest, requires network access.

The Rust integration tests and Playwright tests are complementary:
Rust validates the server-side contract (correct HTML structure,
correct API responses). Playwright validates that the browser
correctly renders and interacts with that contract. If a Rust HTML
structure test passes but the Playwright interactive test fails,
the bug is in the frontend JS. If both fail, the bug is in the
server-side template.

## Implementation Steps

1. Create `e2e-devaipod/` directory with `package.json`,
   `playwright.config.ts`, `fixtures.ts`, `global-setup.ts`,
   `global-teardown.ts`.
2. Write `pod-switcher.spec.ts` implementing scenarios 7-9.
3. Add the `integration-web-runner` stage to the Containerfile.
4. Add `build-integration-web` and `test-integration-web` targets
   to the Justfile.
5. Run locally: `just test-integration-web`.
6. Add to CI workflow.

## References

- [lightweight-review.md](./lightweight-review.md) — git review flow design
- [test-performance.md](./test-performance.md) — integration test performance
- [opencode-webui-fork.md](./opencode-webui-fork.md) — vendored opencode SPA
- `crates/integration-tests/src/harness.rs` — `DevaipodHarness`
- `crates/integration-tests/src/tests/controlplane.rs` — pod switcher Rust tests
- `e2e-devaipod/` — devaipod-specific Playwright tests (to be created)
- `opencode-ui/packages/app/e2e/` — upstream opencode Playwright tests (reference)
- `opencode-ui/packages/app/playwright.config.ts` — upstream Playwright config (reference)

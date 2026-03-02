import {
  createEffect,
  createMemo,
  createSignal,
  For,
  Match,
  onCleanup,
  onMount,
  Show,
  Switch,
} from "solid-js"
import { Button } from "@opencode-ai/ui/button"
import { IconButton } from "@opencode-ai/ui/icon-button"
import { Icon } from "@opencode-ai/ui/icon"
import { Card } from "@opencode-ai/ui/card"
import { Tag } from "@opencode-ai/ui/tag"
import { TextField } from "@opencode-ai/ui/text-field"
import { Collapsible } from "@opencode-ai/ui/collapsible"
import { Checkbox } from "@opencode-ai/ui/checkbox"
import { Spinner } from "@opencode-ai/ui/spinner"
import {
  DevaipodProvider,
  useDevaipod,
  type PodInfo,
  type Proposal,
  type LaunchWorkspaceParams,
} from "@/context/devaipod"

// ---------------------------------------------------------------------------
// Page wrapper — provides context
// ---------------------------------------------------------------------------

export default function PodsPage() {
  return (
    <DevaipodProvider>
      <PodsPageContent />
    </DevaipodProvider>
  )
}

// ---------------------------------------------------------------------------
// Main content
// ---------------------------------------------------------------------------

function PodsPageContent() {
  const ctx = useDevaipod()

  const [showForm, setShowForm] = createSignal(false)
  const [focusedIdx, setFocusedIdx] = createSignal(-1)

  // Keyboard shortcuts
  onMount(() => {
    const handler = (e: KeyboardEvent) => {
      const tag = (e.target as HTMLElement).tagName.toLowerCase()
      const isInput = tag === "input" || tag === "textarea" || (e.target as HTMLElement).isContentEditable

      if (e.key === "n" && !isInput) {
        if (!showForm()) {
          e.preventDefault()
          setShowForm(true)
        }
      }

      if (e.key === "Escape" && showForm()) {
        e.preventDefault()
        setShowForm(false)
      }

      if ((e.key === "ArrowDown" || e.key === "ArrowUp") && !isInput) {
        const total = ctx.pods.length
        if (total === 0) return
        e.preventDefault()
        setFocusedIdx((prev) => {
          if (e.key === "ArrowDown") return prev < 0 ? 0 : Math.min(prev + 1, total - 1)
          return prev < 0 ? total - 1 : Math.max(prev - 1, 0)
        })
      }

      if (e.key === "Enter" && !isInput) {
        const idx = focusedIdx()
        const cards = ctx.pods
        if (idx >= 0 && idx < cards.length) {
          e.preventDefault()
          const card = cards[idx]
          const isRunning = (card.Status ?? "").toLowerCase() === "running"
          if (isRunning) {
            ctx.openPod(card.Name).catch(alertError)
          } else {
            ctx.startPod(card.Name).catch(alertError)
          }
        }
      }
    }
    document.addEventListener("keydown", handler)
    onCleanup(() => document.removeEventListener("keydown", handler))
  })

  const existingPodNames = createMemo(() => new Set(ctx.pods.map((p) => p.Name)))

  const connectionDotClass = createMemo(() => {
    if (ctx.connected === true) return "bg-icon-success-base"
    if (ctx.connected === false) return "bg-icon-critical-base"
    return "bg-border-weak-base"
  })

  // Launch cards that don't yet have a real pod
  const pendingLaunches = createMemo(() => {
    const names = existingPodNames()
    return Object.entries(ctx.launches).filter(([podName]) => !names.has(podName))
  })

  return (
    <div class="h-full overflow-y-auto">
    <div class="mx-auto mt-8 w-full max-w-3xl px-4 pb-16">
      {/* Header */}
      <header class="flex items-center justify-between border-b border-border-base pb-4 mb-6">
        <h1 class="text-18-medium text-text-strong">devaipod</h1>
        <div class="flex items-center gap-3">
          <div class="flex items-center gap-2">
            <div classList={{ "size-2.5 rounded-full": true, [connectionDotClass()]: true }} />
            <span class="text-12-regular text-text-weak">
              {ctx.connected === true ? "Connected" : ctx.connected === false ? "Disconnected" : "Connecting..."}
            </span>
          </div>
          <Button variant="ghost" size="small" onClick={() => ctx.refresh()}>
              Refresh
            </Button>
            <a
              href="/docs/"
              target="_blank"
              rel="noopener noreferrer"
              class="text-11-regular text-text-weak hover:text-text-secondary-base transition-colors"
            >
              Docs
            </a>
        </div>
      </header>

      {/* Error banner */}
      <Show when={ctx.error}>
        <Card variant="error" class="mb-4 p-3">
          <span class="text-12-regular">{ctx.error}</span>
        </Card>
      </Show>

      {/* Launch form section */}
      <div class="mb-6">
        <Show
          when={showForm()}
          fallback={
            <Button variant="primary" icon="plus" onClick={() => setShowForm(true)}>
              New Workspace
            </Button>
          }
        >
          <LaunchForm onClose={() => setShowForm(false)} />
        </Show>
      </div>

      {/* Advisor placeholder when no advisor pod exists */}
      <Show when={!ctx.hasAdvisor()}>
        <AdvisorPlaceholder />
      </Show>

      {/* Pending launch cards */}
      <For each={pendingLaunches()}>
        {([podName, info]) => <LaunchCard podName={podName} state={info} />}
      </For>

      {/* Pod list */}
      <Show
        when={ctx.pods.length > 0 || pendingLaunches().length > 0}
        fallback={
          <Show when={ctx.connected !== undefined}>
            <div class="flex flex-col items-center justify-center py-12 text-text-weak">
              <div class="mb-3 opacity-30">
                <Icon name="server" size="large" />
              </div>
              <p class="text-14-medium mb-1">No workspaces found</p>
              <p class="text-12-regular">Launch one with the button above</p>
            </div>
          </Show>
        }
      >
        <div class="flex flex-col gap-3">
          <For each={ctx.pods}>
            {(pod, index) => (
              <PodCard
                pod={pod}
                focused={focusedIdx() === index()}
                onFocus={() => setFocusedIdx(index())}
              />
            )}
          </For>
        </div>
      </Show>
    </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Launch form
// ---------------------------------------------------------------------------

function LaunchForm(props: { onClose: () => void }) {
  const ctx = useDevaipod()

  const [repoUrl, setRepoUrl] = createSignal("")
  const [task, setTask] = createSignal("")
  const [podName, setPodName] = createSignal("")
  const [imageOverride, setImageOverride] = createSignal("")
  const [scopes, setScopes] = createSignal<string[]>([])
  const [gatorImage, setGatorImage] = createSignal("")
  const [readOnly, setReadOnly] = createSignal(true)
  const [devcontainerJson, setDevcontainerJson] = createSignal("")
  const [submitting, setSubmitting] = createSignal(false)
  const [error, setError] = createSignal("")

  function addScope() {
    setScopes((prev) => [...prev, ""])
  }

  function removeScope(index: number) {
    setScopes((prev) => prev.filter((_, i) => i !== index))
  }

  function updateScope(index: number, value: string) {
    setScopes((prev) => prev.map((s, i) => (i === index ? value : s)))
  }

  async function handleSubmit(e: Event) {
    e.preventDefault()
    const url = repoUrl().trim()
    if (!url) {
      setError("Repository URL is required")
      return
    }

    setSubmitting(true)
    setError("")

    try {
      const params: LaunchWorkspaceParams = { source: url }
      const t = task().trim()
      if (t) params.task = t
      const n = podName().trim()
      if (n) params.name = n
      const img = imageOverride().trim()
      if (img) params.image = img
      const s = scopes().map((v) => v.trim()).filter(Boolean)
      if (s.length > 0) params.service_gator_scopes = s
      const gi = gatorImage().trim()
      if (gi) params.service_gator_image = gi
      if (readOnly()) params.service_gator_ro = true
      const dcj = devcontainerJson().trim()
      if (dcj) params.devcontainer_json = dcj

      await ctx.launchWorkspace(params)
      props.onClose()
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <Card class="p-5">
      <h2 class="text-14-medium text-text-strong mb-4">Launch New Workspace</h2>
      <form onSubmit={handleSubmit}>
        <div class="flex flex-col gap-4">
          <TextField
            label="Repository URL"
            placeholder="https://github.com/org/repo or issue/PR URL"
            value={repoUrl()}
            onChange={setRepoUrl}
            required
          />
          <TextField
            label="Task (optional)"
            placeholder="Describe what the agent should work on..."
            value={task()}
            onChange={setTask}
            multiline
          />

          <Collapsible variant="ghost">
            <Collapsible.Trigger class="flex items-center gap-2 text-12-regular text-text-weak cursor-pointer">
              <Collapsible.Arrow />
              Advanced options
            </Collapsible.Trigger>
            <Collapsible.Content class="mt-3 flex flex-col gap-4">
              <TextField
                label="Pod name (optional)"
                placeholder="Auto-generated from repo name"
                value={podName()}
                onChange={setPodName}
              />
              <TextField
                label="Container image (optional)"
                placeholder="Use devcontainer.json by default"
                description="Override the image built from devcontainer.json"
                value={imageOverride()}
                onChange={setImageOverride}
              />

              <div>
                <label class="text-12-regular text-text-weak block mb-1">Service-gator scopes</label>
                <p class="text-11-regular text-text-weak opacity-70 mb-2">
                  Control AI agent access to external services (e.g. github:org/repo, github:org/*:write)
                </p>
                <div class="flex flex-col gap-2">
                  <For each={scopes()}>
                    {(scope, index) => (
                      <div class="flex gap-2 items-center">
                        <TextField
                          hideLabel
                          label="Scope"
                          placeholder="github:org/repo or github:org/*:write"
                          value={scope}
                          onChange={(v) => updateScope(index(), v)}
                          class="flex-1"
                        />
                        <IconButton
                          icon="close-small"
                          size="small"
                          variant="ghost"
                          onClick={() => removeScope(index())}
                        />
                      </div>
                    )}
                  </For>
                </div>
                <Button
                  variant="ghost"
                  size="small"
                  icon="plus-small"
                  class="mt-2"
                  onClick={addScope}
                  type="button"
                >
                  Add scope
                </Button>
              </div>

              <Checkbox
                checked={readOnly()}
                onChange={setReadOnly}
              >
                Read-only mode (default; uncheck to enable write scopes)
              </Checkbox>

              <TextField
                label="Service-gator image (optional)"
                placeholder="Default: ghcr.io/cgwalters/service-gator:latest"
                value={gatorImage()}
                onChange={setGatorImage}
              />

              <TextField
                label="Devcontainer JSON override (optional)"
                placeholder='{"image": "ghcr.io/bootc-dev/devenv-debian", "capAdd": ["SYS_ADMIN"], ...}'
                description="Full devcontainer.json to use instead of the repo's. Accepts JSONC (comments allowed)."
                value={devcontainerJson()}
                onChange={setDevcontainerJson}
                multiline
              />
            </Collapsible.Content>
          </Collapsible>
        </div>

        <div class="flex gap-3 mt-5">
          <Button variant="primary" type="submit" disabled={submitting()}>
            {submitting() ? "Launching..." : "Launch"}
          </Button>
          <Button variant="ghost" type="button" onClick={props.onClose}>
            Cancel
          </Button>
        </div>

        <Show when={error()}>
          <Card variant="error" class="mt-4 p-3">
            <span class="text-12-regular">{error()}</span>
          </Card>
        </Show>
      </form>
    </Card>
  )
}

// ---------------------------------------------------------------------------
// Advisor placeholder
// ---------------------------------------------------------------------------

function AdvisorPlaceholder() {
  const ctx = useDevaipod()
  const [launching, setLaunching] = createSignal(false)

  async function handleLaunch() {
    setLaunching(true)
    try {
      await ctx.launchAdvisor()
    } catch (err) {
      alertError(err)
    } finally {
      setLaunching(false)
    }
  }

  return (
    <Card class="mb-3 p-4 border-l-2 border-l-violet-600">
      <div class="flex items-center justify-between mb-2">
        <span class="text-14-medium text-text-strong">advisor</span>
        <Tag class="text-text-weak">not running</Tag>
      </div>
      <p class="text-12-regular text-text-weak italic mb-3">
        The advisor agent observes your pods and suggests actions.
      </p>
      <Button variant="primary" onClick={handleLaunch} disabled={launching()}>
        {launching() ? "Launching..." : "Launch Advisor"}
      </Button>
    </Card>
  )
}

// ---------------------------------------------------------------------------
// In-flight launch card
// ---------------------------------------------------------------------------

function LaunchCard(props: { podName: string; state: { state: string; error?: string } }) {
  const ctx = useDevaipod()
  const shortName = () => props.podName.replace("devaipod-", "")

  return (
    <Card
      variant={props.state.state === "failed" ? "error" : "info"}
      class="mb-3 p-4"
    >
      <div class="flex items-center justify-between mb-2">
        <span class="text-14-medium text-text-strong">{shortName()}</span>
        <Tag>
          {props.state.state === "launching" ? "launching" : "failed"}
        </Tag>
      </div>
      <Switch>
        <Match when={props.state.state === "launching"}>
          <div class="flex items-center gap-2 text-12-regular text-text-weak">
            <Spinner class="size-3.5" />
            Creating workspace...
          </div>
        </Match>
        <Match when={props.state.state === "failed"}>
          <p class="text-12-regular text-text-critical-base mb-3 break-words">
            {props.state.error ?? "Unknown error"}
          </p>
          <Button
            variant="ghost"
            size="small"
            onClick={() => ctx.dismissLaunch(props.podName)}
          >
            Dismiss
          </Button>
        </Match>
      </Switch>
    </Card>
  )
}

// ---------------------------------------------------------------------------
// Pod card
// ---------------------------------------------------------------------------

function PodCard(props: { pod: PodInfo; focused: boolean; onFocus: () => void }) {
  const ctx = useDevaipod()
  const [collapsed, setCollapsed] = createSignal(false)
  const [actionError, setActionError] = createSignal("")

  const shortName = () => props.pod.Name.replace("devaipod-", "")
  const isAdvisor = () => shortName() === "advisor"
  const isRunning = () => (props.pod.Status ?? "").toLowerCase() === "running"

  const labels = () => props.pod.Labels ?? {}
  const repo = () => labels()["io.devaipod.repo"] ?? ""
  const taskLabel = () => labels()["io.devaipod.task"] ?? ""
  const mode = () => labels()["io.devaipod.mode"] ?? ""

  const agentStatus = () => ctx.agentStatus[props.pod.Name]

  // Health status
  const health = createMemo(() => {
    if (!isRunning()) return { cls: "stopped" as const, label: "Stopped" }
    const nonInfra = (props.pod.Containers ?? []).filter((c) => !c.Names.includes("-infra"))
    const stopped = nonInfra.filter((c) => c.Status !== "running")
    if (stopped.length === 0) return { cls: "healthy" as const, label: "Healthy" }
    const names = stopped.map((c) => c.Names.replace(props.pod.Name + "-", "")).join(", ")
    return { cls: "degraded" as const, label: `${names} down` }
  })

  const healthTagClass = createMemo(() => {
    const h = health().cls
    if (h === "healthy") return "bg-icon-success-base/20 text-icon-success-base"
    if (h === "degraded") return "bg-icon-warning-base/20 text-icon-warning-base"
    return "bg-icon-critical-base/20 text-icon-critical-base"
  })

  // Agent status display
  const agentActivityIcon = createMemo(() => {
    const s = agentStatus()
    if (!s) return null
    switch (s.activity) {
      case "Working":
        return { char: "\u25CF", cls: "text-icon-success-base" }
      case "Idle":
        return { char: "\u25CB", cls: "text-icon-info-base" }
      case "Stopped":
        return { char: "\u25CC", cls: "text-text-weak" }
      default:
        return { char: "\u2026", cls: "text-text-weak" }
    }
  })

  const agentStatusText = createMemo(() => {
    const s = agentStatus()
    if (!s) return ""
    if (s.current_tool) return `\u2192 ${s.current_tool}`
    if (s.status_line) return s.status_line
    return s.activity
  })

  async function withErrorHandling(fn: () => Promise<void>) {
    setActionError("")
    try {
      await fn()
    } catch (err) {
      setActionError(err instanceof Error ? err.message : String(err))
    }
  }

  let cardRef: HTMLDivElement | undefined

  // Focus management
  createEffect(() => {
    if (props.focused && cardRef) {
      cardRef.focus({ preventScroll: true })
    }
  })

  return (
    <Card
      ref={cardRef}
      tabIndex={0}
      onFocus={props.onFocus}
      classList={{
        "p-0 transition-colors": true,
        "ring-2 ring-border-active-base": props.focused,
        "border-l-2 border-l-violet-600": isAdvisor(),
      }}
    >
      {/* Header — click to toggle */}
      <button
        type="button"
        class="w-full flex items-center justify-between p-4 cursor-pointer select-none text-left"
        onClick={() => setCollapsed((c) => !c)}
      >
        <span class="text-14-medium text-text-strong">{shortName()}</span>
        <div class="flex items-center gap-2">
          <span
            class="text-10-regular uppercase px-1.5 py-0.5 rounded"
            classList={{ [healthTagClass()]: true }}
          >
            {health().label}
          </span>
          <Icon
            name="chevron-down"
            size="small"
            class="transition-transform"
            classList={{ "rotate-[-90deg]": collapsed() }}
          />
        </div>
      </button>

      <Show when={!collapsed()}>
        {/* Metadata */}
        <div class="px-4 pb-2 text-12-regular text-text-weak flex flex-col gap-0.5">
          <Show when={repo()}>
            <div>
              <span class="text-text-weak">Repo: </span>
              <span class="text-text-secondary-base">{repo()}</span>
            </div>
          </Show>
          <Show when={taskLabel()}>
            <div>
              <span class="text-text-weak">Task: </span>
              <span class="text-text-secondary-base">
                {taskLabel().length > 100 ? taskLabel().substring(0, 100) + "..." : taskLabel()}
              </span>
            </div>
          </Show>
          <Show when={mode()}>
            <div>
              <span class="text-text-weak">Mode: </span>
              <span class="text-text-secondary-base">{mode()}</span>
            </div>
          </Show>
          <div>
            <span class="text-text-weak">Created: </span>
            <span class="text-text-secondary-base">{formatDate(props.pod.Created)}</span>
          </div>
        </div>

        {/* Agent status line */}
        <Show when={isRunning() && agentActivityIcon()}>
          <div class="flex items-center gap-2 px-4 py-2 text-12-regular text-text-weak border-t border-border-base">
            <span classList={{ [agentActivityIcon()!.cls]: true }}>
              {agentActivityIcon()!.char}
            </span>
            <span class="flex-1 truncate">{agentStatusText()}</span>
            <Show when={agentStatus()?.session_count && agentStatus()!.session_count! > 1}>
              <span class="text-11-regular text-text-weak">
                ({agentStatus()!.session_count} sessions)
              </span>
            </Show>
          </div>
        </Show>

        {/* Actions */}
        <div class="flex gap-2 px-4 py-3 border-t border-border-base">
          <Show when={isRunning()}>
            <Button
              variant="primary"
              size="small"
              onClick={() => withErrorHandling(() => ctx.openPod(props.pod.Name))}
            >
              Open
            </Button>
            <Button
              variant="secondary"
              size="small"
              icon="stop"
              onClick={() => withErrorHandling(() => ctx.stopPod(props.pod.Name))}
            >
              Stop
            </Button>
          </Show>
          <Show when={!isRunning()}>
            <Button
              variant="secondary"
              size="small"
              onClick={() => withErrorHandling(() => ctx.startPod(props.pod.Name))}
            >
              Start
            </Button>
          </Show>
          {(() => {
            const needsUpdate = () => ctx.enrichment[props.pod.Name]?.needs_update === true
            return (
              <Button
                variant={needsUpdate() ? "secondary" : "ghost"}
                size="small"
                onClick={() => {
                  if (confirm(`Recreate workspace "${shortName()}"? It will be deleted and recreated with the same repo.`))
                    withErrorHandling(() => ctx.recreatePod(props.pod.Name))
                }}
              >
                {needsUpdate() ? "Recreate (update available)" : "Recreate"}
              </Button>
            )
          })()}
          <Show when={!isRunning()}>
            <Button
              variant="ghost"
              size="small"
              class="text-text-critical-base"
              onClick={() => {
                if (confirm(`Delete workspace "${shortName()}"? This cannot be undone.`))
                  withErrorHandling(() => ctx.deletePod(props.pod.Name))
              }}
            >
              Delete
            </Button>
          </Show>
        </div>

        {/* Action error */}
        <Show when={actionError()}>
          <Card variant="error" class="mx-4 mb-3 p-2">
            <span class="text-12-regular">{actionError()}</span>
          </Card>
        </Show>

        {/* Advisor proposals inline */}
        <Show when={isAdvisor() && ctx.proposals.length > 0}>
          <ProposalsSection />
        </Show>
      </Show>
    </Card>
  )
}

// ---------------------------------------------------------------------------
// Proposals section (inside advisor card)
// ---------------------------------------------------------------------------

function ProposalsSection() {
  const ctx = useDevaipod()

  return (
    <div class="px-4 pb-4 border-t border-border-base pt-3">
      <div class="flex items-center justify-between mb-3">
        <span class="text-12-medium text-text-secondary-base">Proposals</span>
        <span class="text-11-regular text-text-weak">{ctx.proposals.length} pending</span>
      </div>
      <div class="flex flex-col gap-2">
        <For each={ctx.proposals}>
          {(proposal) => <ProposalCard proposal={proposal} />}
        </For>
      </div>
    </div>
  )
}

function ProposalCard(props: { proposal: Proposal }) {
  const ctx = useDevaipod()
  const p = () => props.proposal

  const priorityClass = createMemo(() => {
    switch (p().priority) {
      case "high":
        return "bg-icon-critical-base/20 text-icon-critical-base"
      case "medium":
        return "bg-icon-warning-base/20 text-icon-warning-base"
      default:
        return "bg-icon-info-base/15 text-icon-info-base"
    }
  })

  function handleLaunch() {
    // Pre-populate the launch form by navigating to top-level
    // For now, just open a simple confirm + launch
    let repo = p().repo
    if (repo && !repo.startsWith("http")) {
      repo = `https://${repo}`
    }
    const task = `${p().title}\n\n${p().rationale}`
    ctx.dismissProposal(p().id)
    ctx.launchWorkspace({ source: repo, task }).catch(alertError)
  }

  return (
    <Card class="p-3">
      <div class="mb-1">
        <span
          class="text-10-regular uppercase px-1.5 py-0.5 rounded mr-2 font-semibold"
          classList={{ [priorityClass()]: true }}
        >
          {p().priority}
        </span>
        <span class="text-13-medium text-text-strong">{p().title}</span>
      </div>
      <div class="text-11-regular text-text-weak mb-1">
        {p().repo}
        <Show when={p().source}>{" \u2014 "}{p().source}</Show>
      </div>
      <p class="text-12-regular text-text-weak mb-2">{p().rationale}</p>
      <div class="flex gap-2">
        <Button variant="primary" size="small" onClick={handleLaunch}>
          Launch
        </Button>
        <Button variant="ghost" size="small" onClick={() => ctx.dismissProposal(p().id)}>
          Dismiss
        </Button>
      </div>
    </Card>
  )
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function formatDate(dateStr: string): string {
  try {
    return new Date(dateStr).toLocaleString()
  } catch {
    return dateStr
  }
}

function alertError(err: unknown) {
  const msg = err instanceof Error ? err.message : String(err)
  alert(msg)
}

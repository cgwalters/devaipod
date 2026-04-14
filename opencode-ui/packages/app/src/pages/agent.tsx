import { createSignal, createEffect, createMemo, createResource, onCleanup, onMount, Show, For, Index } from "solid-js"
import { useParams, useNavigate, A } from "@solidjs/router"
import { DevaipodProvider, useDevaipod } from "@/context/devaipod"
import { AcpSessionProvider, useAcpSession, type ConnectionState, type PaneState } from "@/context/acp-session"
import { apiFetch } from "@/utils/devaipod-api"
import type { AcpMessage, ToolCall, PermissionRequest, PlanEntry, ToolCallDiff } from "@/types/acp"
import type { TimelineEntry } from "@/context/acp-session"
import { Markdown } from "@opencode-ai/ui/markdown"
import { Diff } from "@opencode-ai/ui/diff"
import { BasicTool } from "@opencode-ai/ui/basic-tool"

// ---------------------------------------------------------------------------
// Page wrapper — provides context (standalone, outside the OpenCode stack)
// ---------------------------------------------------------------------------

export default function AgentPage() {
  return (
    <DevaipodProvider>
      <AgentView />
    </DevaipodProvider>
  )
}

// ---------------------------------------------------------------------------
// Agent view — ACP session with navigation bar
// ---------------------------------------------------------------------------

function AgentView() {
  const params = useParams()
  const navigate = useNavigate()
  const ctx = useDevaipod()

  // -- Name normalization ---------------------------------------------------

  const fullName = () => {
    const n = params.name
    return n.startsWith("devaipod-") ? n : `devaipod-${n}`
  }
  const shortName = () => fullName().replace(/^devaipod-/, "")

  // -- Agent status & done state --------------------------------------------

  const agentStatus = () => ctx.agentStatus[fullName()]
  const isDone = () => agentStatus()?.completion_status === "done"
  const sessionTitle = () => agentStatus()?.title || ""

  // Update document title
  createEffect(() => {
    const title = sessionTitle()
    document.title = title ? `${title} — ${shortName()}` : `devaipod — ${shortName()}`
  })

  async function toggleDone() {
    const newStatus = isDone() ? "active" : "done"
    await apiFetch(
      `/api/devaipod/pods/${encodeURIComponent(fullName())}/completion-status`,
      {
        method: "PUT",
        body: JSON.stringify({ status: newStatus }),
      },
    )
    ctx.refresh()
  }

  // -- Agent profile selector -----------------------------------------------

  interface AgentProfileInfo {
    name: string
    command: string[]
    env: Record<string, string>
    isDefault: boolean
  }

  const [profiles, setProfiles] = createSignal<AgentProfileInfo[]>([])
  const [currentProfile, setCurrentProfile] = createSignal("opencode")

  // Immediately fetch pod list so arrows & status are available
  // without waiting for the first poll interval.
  onMount(() => {
    ctx.refresh()

    // Fetch available agent profiles
    apiFetch<Record<string, { command?: string[]; env?: Record<string, string>; is_default?: boolean }>>(
      "/api/devaipod/agent-profiles"
    )
      .then((data) => {
        if (!data || typeof data !== "object") return
        const list: AgentProfileInfo[] = []
        let defaultName = "opencode"
        for (const [name, info] of Object.entries(data)) {
          const p = info as { command?: string[]; env?: Record<string, string>; is_default?: boolean }
          list.push({
            name,
            command: p.command ?? [],
            env: p.env ?? {},
            isDefault: !!p.is_default,
          })
          if (p.is_default) defaultName = name
        }
        setProfiles(list)
        setCurrentProfile(defaultName)
      })
      .catch((e) => {
        console.warn("Failed to fetch agent profiles:", e)
      })
  })

  // -- Pod switcher ---------------------------------------------------------

  const [dropdownOpen, setDropdownOpen] = createSignal(false)

  const runningPods = createMemo(() =>
    ctx.pods.filter((p) => p.Status.toLowerCase() === "running"),
  )

  const currentIdx = () =>
    runningPods().findIndex((p) => p.Name === fullName())
  const canPrev = () => currentIdx() > 0
  const canNext = () =>
    currentIdx() >= 0 && currentIdx() < runningPods().length - 1

  function goPrev() {
    const idx = currentIdx()
    if (idx > 0) {
      navigate(
        `/agent/${encodeURIComponent(runningPods()[idx - 1].Name)}`,
      )
    }
  }

  function goNext() {
    const idx = currentIdx()
    if (idx >= 0 && idx < runningPods().length - 1) {
      navigate(
        `/agent/${encodeURIComponent(runningPods()[idx + 1].Name)}`,
      )
    }
  }

  function switchToPod(podName: string) {
    setDropdownOpen(false)
    navigate(`/agent/${encodeURIComponent(podName)}`)
  }

  // Close dropdown on outside click
  let switcherRef: HTMLDivElement | undefined
  function handleOutsideClick(e: MouseEvent) {
    if (switcherRef && !switcherRef.contains(e.target as Node)) {
      setDropdownOpen(false)
    }
  }
  createEffect(() => {
    if (dropdownOpen()) {
      document.addEventListener("click", handleOutsideClick, true)
    } else {
      document.removeEventListener("click", handleOutsideClick, true)
    }
  })
  onCleanup(() =>
    document.removeEventListener("click", handleOutsideClick, true),
  )

  // Activity dot class for pod switcher items
  function podDotClass(podName: string): string {
    const status = ctx.agentStatus[podName]
    if (!status) return "bg-gray-500"
    if (status.completion_status === "done") return "bg-violet-400"
    switch (status.activity) {
      case "Working":
        return "bg-green-500 animate-[pulse-dot_1.5s_ease-in-out_infinite]"
      case "Idle":
        return "bg-blue-500"
      case "Stopped":
        return "bg-gray-500"
      default:
        return "bg-gray-500"
    }
  }

  function podStatusLabel(podName: string): string {
    const status = ctx.agentStatus[podName]
    if (!status) return ""
    if (status.completion_status === "done") return "done"
    return status.activity
  }

  // -- Forwarded ports for the current pod -----------------------------------

  const currentPod = () => ctx.pods.find((p) => p.Name === fullName())
  const forwardedPorts = () => currentPod()?.ForwardedPorts ?? []

  // Display name for pod trigger button
  const triggerLabel = () => {
    const title = sessionTitle()
    return title || shortName()
  }

  return (
    <div
      class="h-full bg-background-base text-text-strong flex flex-col"
      style={{ overflow: "hidden" }}
    >
      {/* Navigation bar */}
      <div
        id="dbar"
        data-testid="agent-topbar"
        class="flex items-center px-3 gap-2 border-b border-border-base shrink-0"
        style={{ height: "44px" }}
      >
        <A
          href="/pods"
          class="text-text-strong no-underline text-sm font-medium px-3.5 py-1.5 rounded-md bg-fill-element-base border border-border-base hover:bg-fill-element-active hover:border-border-base transition-colors"
        >
          &larr; Pods
        </A>

        <button
          type="button"
          data-testid="done-btn"
          class="text-sm font-medium px-3.5 py-1.5 rounded-md border cursor-pointer transition-colors"
          classList={{
            "bg-[rgba(34,197,94,0.15)] border-[rgba(34,197,94,0.4)] text-[#86efac] hover:bg-[rgba(34,197,94,0.25)] hover:border-[rgba(34,197,94,0.6)]":
              isDone(),
            "bg-fill-element-base border-border-base text-text-strong hover:bg-fill-element-active hover:border-border-base":
              !isDone(),
          }}
          title="Mark this pod as done"
          onClick={toggleDone}
        >
          {isDone() ? "Done" : "Mark Done"}
        </button>

        {/* Forwarded ports */}
        <Show when={forwardedPorts().length > 0}>
          <div class="flex items-center gap-1.5 text-[13px] text-text-weak ml-2">
            <span>Ports:</span>
            <Index each={forwardedPorts()}>
              {(port, idx) => (
                <>
                  <Show when={idx > 0}>
                    <span class="opacity-40">,</span>
                  </Show>
                  <a
                    href={`http://${window.location.hostname}:${port().hostPort}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    class="text-text-secondary-base hover:text-text-strong no-underline hover:underline tabular-nums"
                    title={`Open port ${port().containerPort} (host port ${port().hostPort})`}
                  >
                    {port().hostPort}&rarr;{port().containerPort}
                  </a>
                </>
              )}
            </Index>
          </div>
        </Show>

        <span class="flex-1" />

        {/* Agent profile selector */}
        <Show when={profiles().length > 1}>
          <div class="flex items-center gap-1.5" data-testid="profile-selector">
            <span class="text-xs opacity-50">Agent:</span>
            <select
              value={currentProfile()}
              onChange={(e) => setCurrentProfile(e.currentTarget.value)}
              class="bg-fill-element-base border border-border-base text-text-strong text-xs rounded-md px-2 py-1 outline-none cursor-pointer"
              data-testid="profile-select"
            >
              <For each={profiles()}>
                {(profile) => (
                  <option value={profile.name}>{profile.name}</option>
                )}
              </For>
            </select>
          </div>
        </Show>

        {/* Pod switcher */}
        <div
          ref={switcherRef}
          class="flex items-center gap-0.5 relative"
        >
          <button
            type="button"
            data-testid="prev-pod"
            class="px-2 py-1.5 text-base min-w-[30px] text-center text-text-strong bg-fill-element-base border border-border-base rounded-md cursor-pointer transition-colors hover:bg-fill-element-active disabled:opacity-30 disabled:cursor-default disabled:pointer-events-none"
            title="Previous pod"
            disabled={!canPrev()}
            onClick={goPrev}
          >
            &larr;
          </button>

          <button
            type="button"
            data-testid="pod-trigger"
            class="relative min-w-[140px] text-left pr-7 text-sm font-medium px-3.5 py-1.5 rounded-md bg-fill-element-base border border-border-base text-text-strong cursor-pointer transition-colors hover:bg-fill-element-active"
            title="Switch pod"
            onClick={() => setDropdownOpen((v) => !v)}
          >
            <span class="truncate block">{triggerLabel()}</span>
            <span class="absolute right-2.5 top-1/2 -translate-y-1/2 text-[11px] opacity-60">
              &#9662;
            </span>
          </button>

          <button
            type="button"
            data-testid="next-pod"
            class="px-2 py-1.5 text-base min-w-[30px] text-center text-text-strong bg-fill-element-base border border-border-base rounded-md cursor-pointer transition-colors hover:bg-fill-element-active disabled:opacity-30 disabled:cursor-default disabled:pointer-events-none"
            title="Next pod"
            disabled={!canNext()}
            onClick={goNext}
          >
            &rarr;
          </button>

          {/* Dropdown */}
          <Show when={dropdownOpen()}>
            <div
              data-testid="pod-dropdown"
              class="absolute top-full right-0 mt-1 min-w-[280px] max-h-[360px] overflow-y-auto bg-surface-base border border-border-base rounded-lg shadow-[0_8px_24px_rgba(0,0,0,0.5)] z-[100] p-1"
            >
              <For each={runningPods()}>
                {(pod) => {
                  const podShort = () =>
                    pod.Name.replace(/^devaipod-/, "")
                  const podTitle = () =>
                    ctx.agentStatus[pod.Name]?.title
                  const isCurrent = () => pod.Name === fullName()
                  return (
                    <button
                      type="button"
                      data-testid="pod-item"
                      class="flex items-center gap-2 w-full text-left px-3 py-2 rounded-md text-[13px] text-text-strong border-none bg-transparent cursor-pointer transition-colors hover:bg-fill-element-base"
                      classList={{
                        "bg-fill-element-base font-semibold":
                          isCurrent(),
                      }}
                      onClick={() => switchToPod(pod.Name)}
                    >
                      <span
                        class="w-2 h-2 rounded-full shrink-0"
                        classList={{
                          [podDotClass(pod.Name)]: true,
                        }}
                      />
                      <span class="flex-1 truncate">
                        {podTitle() || podShort()}
                      </span>
                      <Show when={podStatusLabel(pod.Name)}>
                        <span class="text-[11px] opacity-55 whitespace-nowrap">
                          {podStatusLabel(pod.Name)}
                        </span>
                      </Show>
                    </button>
                  )
                }}
              </For>
              <Show when={runningPods().length === 0}>
                <div class="px-3 py-2 text-[13px] opacity-50">
                  No running pods
                </div>
              </Show>
            </div>
          </Show>
        </div>
      </div>

      {/* Content area: ACP session */}
      <AcpSessionProvider podName={fullName()}>
        <AcpContent />
      </AcpSessionProvider>
    </div>
  )
}

// ---------------------------------------------------------------------------
// ACP content area — message list, tool calls, permissions, prompt input
// ---------------------------------------------------------------------------

function AcpContent() {
  const acp = useAcpSession()
  const ctx = useDevaipod()
  const params = useParams()
  const fullName = () => params.name ? decodeURIComponent(params.name) : ""

  const [showInfo, setShowInfo] = createSignal(false)
  const [gatorScopes, setGatorScopes] = createSignal<Record<string, unknown> | null>(null)
  // Persist tab names in localStorage keyed by pod name
  const tabNamesKey = () => `devaipod-tab-names-${fullName()}`
  const loadTabNames = (): Record<string, string> => {
    try {
      const raw = localStorage.getItem(tabNamesKey())
      return raw ? JSON.parse(raw) : {}
    } catch { return {} }
  }
  const [tabNames, setTabNames] = createSignal<Record<string, string>>(loadTabNames())
  const [editingTab, setEditingTab] = createSignal<string | null>(null)

  // Save tab names whenever they change
  createEffect(() => {
    const names = tabNames()
    if (Object.keys(names).length > 0) {
      localStorage.setItem(tabNamesKey(), JSON.stringify(names))
    }
  })

  // Fetch gator scopes when info panel opens
  createEffect(() => {
    if (showInfo() && fullName()) {
      ctx.getGatorScopes(fullName()).then((r) => {
        if (r.scopes) setGatorScopes(r.scopes as Record<string, unknown>)
      }).catch(() => {})
    }
  })

  // Collect unique tools used in this session
  const usedTools = createMemo(() => {
    const tools = new Map<string, string>()
    for (const tc of Object.values(acp.toolCalls)) {
      tools.set(tc.title || tc.toolCallId, tc.kind || "other")
    }
    return [...tools.entries()].map(([name, kind]) => ({ name, kind }))
  })

  return (
    <div
      class="flex-1 flex min-h-0"
      data-testid="acp-content"
    >
      {/* Main content column */}
      <div class="flex-1 flex flex-col min-h-0 min-w-0">

      {/* Status bar */}
      <div
        class="flex items-center px-3 py-1.5 gap-2 text-xs shrink-0"
        style={{
          "background-color": "#2a2323",
          "border-bottom": "1px solid rgba(255,255,255,0.12)",
        }}
        data-testid="acp-status-bar"
      >
        <ConnectionIndicator state={acp.connectionState} />
        <Show when={acp.agentInfo}>
          {(info) => (
            <span
              class="text-text-dimmed font-mono"
              data-testid="agent-info"
              title={`Agent: ${info().name} v${info().version}`}
            >
              {info().title || info().name} <span class="opacity-50">v{info().version}</span>
            </span>
          )}
        </Show>
        <Show when={acp.sessionMode}>
          {(mode) => (
            <span
              class="px-2 py-0.5 rounded bg-fill-element-base border border-border-base text-text-dimmed font-medium"
              data-testid="session-mode-indicator"
              title={`Session mode: ${mode().currentModeId}`}
            >
              {mode().currentModeId}
            </span>
          )}
        </Show>
        <span class="flex-1" />
        <Show when={acp.hiddenSessions.length > 0}>
          <RestoreDropdown tabNames={tabNames()} />
        </Show>
        <Show when={acp.panes.length > 0}>
          <button
            type="button"
            class="px-2 py-0.5 rounded text-xs cursor-pointer border border-border-base text-text-dimmed hover:bg-surface-secondary transition-colors"
            onClick={() => acp.splitPane()}
            title="Add a new pane"
          >
            Add Pane
          </button>
        </Show>
        <button
          type="button"
          class="px-2 py-0.5 rounded text-xs cursor-pointer border border-border-base text-text-dimmed hover:bg-surface-secondary transition-colors"
          classList={{ "bg-surface-secondary": showInfo() }}
          onClick={() => setShowInfo(!showInfo())}
          title="Show agent details, MCP servers, and tools"
        >
          Details
        </button>
      </div>

      {/* Panes container */}
      <div class="flex-1 flex min-h-0" data-testid="panes-container">
        <Index each={acp.panes}>
          {(pane, idx) => (
            <>
              <PaneWithTabs
                pane={pane()}
                isLast={idx === acp.panes.length - 1}
                isActive={pane().id === acp.activePaneId}
                podName={fullName()}
                tabNames={tabNames()}
                editingTab={editingTab()}
                onSetTabNames={setTabNames}
                onSetEditingTab={setEditingTab}
              />
              <Show when={idx < acp.panes.length - 1}>
                <ResizeDivider
                  leftPaneId={pane().id}
                  rightPaneId={acp.panes[idx + 1].id}
                />
              </Show>
            </>
          )}
        </Index>
      </div>
      </div>

      {/* Info side panel */}
      <Show when={showInfo()}>
        <div
          class="w-72 shrink-0 border-l border-border-base overflow-y-auto text-xs"
          style={{ "background-color": "#1c1717" }}
        >
          <div class="p-3 space-y-4">
            <div>
              <div class="font-medium text-text-dimmed mb-2 uppercase tracking-wider text-[10px]">
                Slash Commands
              </div>
              <Show when={acp.availableCommands.length > 0} fallback={<div class="opacity-40">None</div>}>
                <div class="space-y-1">
                  <For each={acp.availableCommands}>
                    {(cmd) => (
                      <div class="flex flex-col gap-0.5">
                        <span class="text-blue-400 font-mono">/{cmd.name}</span>
                        <Show when={cmd.description}>
                          <span class="opacity-50 text-[10px]">{cmd.description}</span>
                        </Show>
                      </div>
                    )}
                  </For>
                </div>
              </Show>
            </div>

            <div>
              <div class="font-medium text-text-dimmed mb-2 uppercase tracking-wider text-[10px]">
                Service Gator
              </div>
              <Show when={gatorScopes()} fallback={<div class="opacity-40">Loading...</div>}>
                <pre class="text-[10px] opacity-70 whitespace-pre-wrap break-all">
                  {JSON.stringify(gatorScopes(), null, 2)}
                </pre>
              </Show>
            </div>

            <Show when={usedTools().length > 0}>
              <div>
                <div class="font-medium text-text-dimmed mb-2 uppercase tracking-wider text-[10px]">
                  Tools Used
                </div>
                <div class="space-y-1">
                  <For each={usedTools()}>
                    {(tool) => (
                      <div class="flex items-center gap-2">
                        <span class="px-1 py-0.5 rounded bg-fill-element-base text-[10px] font-mono">{tool.kind}</span>
                        <span class="truncate">{tool.name}</span>
                      </div>
                    )}
                  </For>
                </div>
              </div>
            </Show>
          </div>
        </div>
      </Show>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Resize divider component
// ---------------------------------------------------------------------------

function ResizeDivider(props: {
  leftPaneId: string
  rightPaneId: string
}) {
  const acp = useAcpSession()
  const [isDragging, setIsDragging] = createSignal(false)

  function handleMouseDown(e: MouseEvent) {
    e.preventDefault()
    setIsDragging(true)

    const leftPane = acp.panes.find((p) => p.id === props.leftPaneId)
    const rightPane = acp.panes.find((p) => p.id === props.rightPaneId)
    if (!leftPane || !rightPane) return

    const startX = e.clientX
    const startLeftWidth = leftPane.width
    const startRightWidth = rightPane.width

    function handleMouseMove(e: MouseEvent) {
      const container = document.querySelector('[data-testid="panes-container"]') as HTMLElement
      if (!container) return

      const containerWidth = container.offsetWidth
      const deltaX = e.clientX - startX
      const deltaPercent = (deltaX / containerWidth) * 100

      const newLeftWidth = Math.max(20, Math.min(80, startLeftWidth + deltaPercent))
      const newRightWidth = Math.max(20, Math.min(80, startRightWidth - deltaPercent))

      // Only update if both panes respect minimum width
      if (newLeftWidth >= 20 && newRightWidth >= 20) {
        acp.setPaneWidth(props.leftPaneId, newLeftWidth)
        acp.setPaneWidth(props.rightPaneId, newRightWidth)
      }
    }

    function handleMouseUp() {
      setIsDragging(false)
      document.removeEventListener("mousemove", handleMouseMove)
      document.removeEventListener("mouseup", handleMouseUp)
    }

    document.addEventListener("mousemove", handleMouseMove)
    document.addEventListener("mouseup", handleMouseUp)
  }

  return (
    <div
      class="shrink-0 cursor-col-resize transition-colors"
      classList={{
        "bg-blue-500/30": isDragging(),
        "hover:bg-blue-500/20": !isDragging(),
      }}
      style={{ width: "4px" }}
      onMouseDown={handleMouseDown}
    />
  )
}

// ---------------------------------------------------------------------------
// Pane with tabs — shows tab bar and active session content
// ---------------------------------------------------------------------------

function PaneWithTabs(props: {
  pane: { id: string; tabs: string[]; activeTab: string; width: number }
  isLast: boolean
  isActive: boolean
  podName: string
  tabNames: Record<string, string>
  editingTab: string | null
  onSetTabNames: (fn: (prev: Record<string, string>) => Record<string, string>) => void
  onSetEditingTab: (sessionId: string | null) => void
}) {
  const acp = useAcpSession()

  const getLabel = (sessionId: string) => {
    const custom = props.tabNames[sessionId]
    if (custom) return custom
    const s = acp.sessions.find((s) => s.id === sessionId)
    if (s?.created) {
      return new Date(s.created).toLocaleString(undefined, {
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit",
      })
    }
    return sessionId.slice(0, 10)
  }

  return (
    <div
      class="flex flex-col min-h-0 min-w-0"
      style={{
        "flex-basis": `${props.pane.width}%`,
        "flex-grow": 0,
        "flex-shrink": 0,
        "min-width": "200px",
      }}
      data-testid="pane-with-tabs"
      onClick={() => acp.setActivePane(props.pane.id)}
    >
      {/* Per-pane tab bar (drop target for tabs dragged from other panes) */}
      <div
        class="flex items-end gap-0 px-2 pt-1 shrink-0 overflow-x-auto scrollbar-none"
        style={{
          "scrollbar-width": "none",
          "background-color": "#1c1717",
          "border-bottom": props.isActive ? "1px solid rgba(96,165,250,0.3)" : "1px solid rgba(255,255,255,0.12)",
          height: "38px",
        }}
        data-testid="pane-tabs"
        onDragOver={(e) => {
          e.preventDefault()
          e.dataTransfer!.dropEffect = "move"
        }}
        onDrop={(e) => {
          e.preventDefault()
          const data = e.dataTransfer?.getData("text/plain")
          if (!data) return
          try {
            const { sessionId, fromPaneId } = JSON.parse(data)
            if (fromPaneId === props.pane.id) {
              // Same pane: move to end
              acp.moveTab(sessionId, fromPaneId, props.pane.id, "__end__")
            } else {
              acp.moveTab(sessionId, fromPaneId, props.pane.id)
            }
          } catch {}
        }}
      >
        <For each={props.pane.tabs}>
          {(sessionId) => {
            const isActive = () => sessionId === props.pane.activeTab
            const isEditing = () => props.editingTab === sessionId
            const label = () => getLabel(sessionId)

            return (
              <div
                class="px-3 py-1.5 text-xs cursor-grab transition-colors shrink-0 flex items-center gap-1.5"
                draggable={!isEditing()}
                onDragStart={(e) => {
                  e.dataTransfer!.setData("text/plain", JSON.stringify({
                    sessionId,
                    fromPaneId: props.pane.id,
                  }))
                  e.dataTransfer!.effectAllowed = "move"
                }}
                style={{
                  "border-top-left-radius": "6px",
                  "border-top-right-radius": "6px",
                  border: isActive()
                    ? "1px solid rgba(255,255,255,0.12)"
                    : "1px solid transparent",
                  "border-bottom": "none",
                  "background-color": isActive() ? "#2a2323" : "transparent",
                  color: isActive() ? "#e8e2e2" : "rgba(232,226,226,0.5)",
                  "margin-bottom": isActive() ? "-1px" : "0",
                  position: "relative",
                  "z-index": isActive() ? "1" : "0",
                }}
                onDragOver={(e) => {
                  e.preventDefault()
                  e.stopPropagation()
                  e.dataTransfer!.dropEffect = "move"
                }}
                onDrop={(e) => {
                  e.preventDefault()
                  e.stopPropagation()
                  const data = e.dataTransfer?.getData("text/plain")
                  if (!data) return
                  try {
                    const { sessionId: draggedId, fromPaneId } = JSON.parse(data)
                    if (draggedId === sessionId) return
                    // Determine if dropping on left or right half of the tab
                    const rect = (e.currentTarget as HTMLElement).getBoundingClientRect()
                    const dropOnRightHalf = e.clientX > rect.left + rect.width / 2
                    if (dropOnRightHalf) {
                      // Insert after this tab: find the next tab's ID
                      const tabs = props.pane.tabs
                      const idx = tabs.indexOf(sessionId)
                      const nextTab = idx < tabs.length - 1 ? tabs[idx + 1] : "__end__"
                      acp.moveTab(draggedId, fromPaneId, props.pane.id, nextTab)
                    } else {
                      acp.moveTab(draggedId, fromPaneId, props.pane.id, sessionId)
                    }
                  } catch {}
                }}
                onClick={(e) => {
                  e.stopPropagation()
                  if (!isActive() && !isEditing()) {
                    acp.setActiveTab(props.pane.id, sessionId)
                    acp.setActivePane(props.pane.id)
                  }
                }}
                onDblClick={(e) => {
                  e.stopPropagation()
                  props.onSetEditingTab(sessionId)
                }}
                title="Drag to reorder or move between panes. Double-click to rename."
              >
                <Show when={isEditing()} fallback={<span>{label()}</span>}>
                  <input
                    type="text"
                    class="bg-transparent border-b border-blue-400 outline-none text-xs w-24"
                    value={props.tabNames[sessionId] || ""}
                    placeholder={label()}
                    autofocus
                    onBlur={(e) => {
                      const val = e.currentTarget.value.trim()
                      if (val) {
                        props.onSetTabNames((prev) => ({
                          ...prev,
                          [sessionId]: val,
                        }))
                      }
                      props.onSetEditingTab(null)
                    }}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") e.currentTarget.blur()
                      if (e.key === "Escape") {
                        props.onSetEditingTab(null)
                      }
                    }}
                    onClick={(e) => e.stopPropagation()}
                  />
                </Show>
                <button
                  type="button"
                  class="ml-0.5 text-[10px] opacity-40 hover:opacity-100 transition-opacity"
                  onClick={(e) => {
                    e.stopPropagation()
                    acp.closeTab(props.pane.id, sessionId)
                  }}
                  title="Hide session (can be restored from status bar)"
                >
                  x
                </button>
              </div>
            )
          }}
        </For>
        <button
          type="button"
          class="px-2 py-1.5 text-xs cursor-pointer shrink-0 transition-colors"
          style={{
            color: "rgba(96,165,250,0.8)",
            "border-top-left-radius": "6px",
            "border-top-right-radius": "6px",
          }}
          onClick={(e) => {
            e.stopPropagation()
            acp.setActivePane(props.pane.id)
            acp.newSession()
          }}
          title="New session"
        >
          +
        </button>
      </div>

      {/* Active tab content */}
      <Show when={props.pane.activeTab}>
        <SessionPane
          sessionId={props.pane.activeTab}
          podName={props.podName}
        />
      </Show>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Session pane — shows messages, tool calls, and prompt input for one session
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Session pane
// ---------------------------------------------------------------------------

function SessionPane(props: { sessionId: string; podName: string }) {
  const acp = useAcpSession()
  const sessionData = () => acp.getSessionData(props.sessionId)
  const session = () => acp.sessions.find((s) => s.id === props.sessionId)

  const [branchInfo, setBranchInfo] = createSignal("")

  // Fetch git branch info for the workspace
  onMount(() => {
    apiFetch<{ branch?: string; head?: string }>(
      `/api/devaipod/pods/${encodeURIComponent(props.podName)}/pod-api/git/status`
    ).then((r) => {
      if (r.branch) setBranchInfo(r.branch)
    }).catch(() => {})
  })

  const label = () => {
    const s = session()
    if (s?.title) return s.title
    if (s?.created) {
      return new Date(s.created).toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" })
    }
    return props.sessionId.slice(0, 10)
  }

  return (
    <div
      class="flex-1 flex flex-col min-h-0 min-w-0"
      data-testid="session-pane"
    >
      {/* Pane header */}
      <div class="px-3 py-1 text-[10px] opacity-40 border-b border-border-weak-base shrink-0 flex items-center gap-2">
        <span>{label()}</span>
        <Show when={branchInfo()}>
          <span class="font-mono text-blue-400 opacity-70">{branchInfo()}</span>
        </Show>
      </div>

      {/* Scrollable message area */}
      <div
        ref={(el) => {
          let pinned = true
          const THRESHOLD = 60

          function isNearBottom(): boolean {
            return el.scrollHeight - el.scrollTop - el.clientHeight < THRESHOLD
          }

          // Track user scroll intent.
          el.addEventListener("scroll", () => {
            pinned = isNearBottom()
          }, { passive: true })

          // Auto-scroll on DOM changes when pinned.
          const observer = new MutationObserver(() => {
            if (pinned) {
              el.scrollTop = el.scrollHeight
            }
          })
          observer.observe(el, { childList: true, subtree: true, characterData: true })

          // Start at bottom.
          queueMicrotask(() => { el.scrollTop = el.scrollHeight })
        }}
        class="flex-1 overflow-y-auto px-4 py-3"
        data-testid="pane-messages"
      >
        <div class="space-y-3">
        <Show
          when={sessionData().timeline.length > 0 && !sessionData().replaying}
          fallback={
            <Show when={!sessionData().replaying}>
              <div class="flex items-center justify-center h-full">
                <div class="text-sm opacity-40">
                  {acp.connectionState === "connected"
                    ? "Ready. Type a message to begin."
                    : "Connecting to agent..."}
                </div>
              </div>
            </Show>
          }
        >
          {/* Plan display (always at top when present) */}
          <PlanDisplay entries={sessionData().planEntries} />

          {/* Interleaved timeline: messages and tool calls in arrival order */}
          <For each={sessionData().timeline}>
            {(entry: TimelineEntry) => (
              <Show when={entry.kind === "message"} fallback={
                <Show when={sessionData().toolCalls[entry.id]}>
                  {(tc) => {
                    const perm = () => sessionData().pendingPermissions.find(
                      (p) => p.toolCall.toolCallId === entry.id
                    )
                    return (
                      <ToolCallCard
                        toolCall={tc()}
                        pendingPermission={perm()}
                        onRespondPermission={acp.respondPermission}
                      />
                    )
                  }}
                </Show>
              }>
                <Show when={sessionData().messages.find((m) => m.id === entry.id)}>
                  {(msg) => <MessageBubble message={msg()} agentName={acp.agentInfo?.title || acp.agentInfo?.name} />}
                </Show>
              </Show>
            )}
          </For>

          {/* Show indicator only when buffering a code fence */}
          <Show when={acp.isSessionBufferingFence(props.sessionId)}>
            <div class="text-xs opacity-50 py-1 font-mono animate-pulse">
              Writing code...
            </div>
          </Show>

          {/* Orphan permission requests (not associated with a visible tool call) */}
          <For each={sessionData().pendingPermissions.filter(
            (p) => !sessionData().toolCalls[p.toolCall.toolCallId]
          )}>
            {(perm) => (
              <PermissionCard
                request={perm}
                onRespond={acp.respondPermission}
              />
            )}
          </For>
        </Show>
        </div>
      </div>

      {/* Prompt input */}
      <PromptBar
        sessionId={props.sessionId}
        onSend={(text) => acp.sendPrompt(text, props.sessionId)}
        onCancel={acp.cancelPrompt}
        prompting={sessionData().prompting}
        disabled={acp.connectionState !== "connected"}
        availableCommands={acp.availableCommands}
      />
    </div>
  )
}

// ---------------------------------------------------------------------------
// Connection indicator
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Restore hidden sessions dropdown
// ---------------------------------------------------------------------------

function RestoreDropdown(props: { tabNames: Record<string, string> }) {
  const acp = useAcpSession()
  const [open, setOpen] = createSignal(false)

  const hiddenDetails = createMemo(() =>
    acp.hiddenSessions
      .map((id) => {
        const custom = props.tabNames[id]
        if (custom) return { id, label: custom }
        const session = acp.sessions.find((s) => s.id === id)
        return {
          id,
          label: session?.created
            ? new Date(session.created).toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" })
            : id.slice(0, 12),
        }
      })
  )

  return (
    <div class="relative">
      <button
        type="button"
        class="px-2 py-0.5 rounded text-xs cursor-pointer border border-border-base text-text-dimmed hover:bg-surface-secondary transition-colors"
        onClick={() => setOpen(!open())}
        title="Restore hidden sessions"
      >
        Hidden ({acp.hiddenSessions.length})
      </button>
      <Show when={open()}>
        <div
          class="absolute top-full right-0 mt-1 min-w-[200px] max-h-[300px] overflow-y-auto border border-border-base rounded-lg z-[100] p-1"
          style={{ "background-color": "#2a2323", "box-shadow": "0 8px 24px rgba(0,0,0,0.5)" }}
        >
          <For each={hiddenDetails()}>
            {(item) => (
              <button
                type="button"
                class="w-full text-left px-3 py-1.5 text-xs hover:bg-surface-secondary transition-colors"
                onClick={() => {
                  acp.restoreSession(item.id)
                  if (acp.hiddenSessions.length <= 1) setOpen(false)
                }}
              >
                {item.label}
              </button>
            )}
          </For>
        </div>
        <div class="fixed inset-0 z-40" onClick={() => setOpen(false)} />
      </Show>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Connection indicator
// ---------------------------------------------------------------------------

function ConnectionIndicator(props: { state: ConnectionState }) {
  const dotClass = () => {
    switch (props.state) {
      case "connected":
        return "bg-green-500"
      case "connecting":
        return "bg-yellow-500 animate-pulse"
      case "disconnected":
        return "bg-gray-500"
      case "error":
        return "bg-red-500"
    }
  }

  const label = () => {
    switch (props.state) {
      case "connected":
        return "Connected"
      case "connecting":
        return "Connecting..."
      case "disconnected":
        return "Disconnected"
      case "error":
        return "Connection error"
    }
  }

  return (
    <span class="flex items-center gap-1.5" data-testid="connection-status">
      <span class={`w-2 h-2 rounded-full ${dotClass()}`} />
      <span class="opacity-60">{label()}</span>
    </span>
  )
}

// ---------------------------------------------------------------------------
// Message bubble
// ---------------------------------------------------------------------------

function MessageBubble(props: { message: AcpMessage; agentName?: string }) {
  const roleLabel = () => {
    switch (props.message.role) {
      case "user":
        return "You"
      case "assistant":
        return props.agentName || "Assistant"
      case "thought":
        return "Thinking"
    }
  }

  const bubbleClass = () => {
    switch (props.message.role) {
      case "user":
        return "ml-12 bg-blue-950/40 border border-blue-800/30 rounded-lg px-3 py-2"
      case "assistant":
        return "mr-12 bg-surface-base border border-border-weak-base rounded-lg px-3 py-2"
      case "thought":
        return "mr-12 bg-yellow-950/20 border border-yellow-800/20 rounded-lg px-3 py-2 opacity-70"
    }
  }

  const labelClass = () => {
    switch (props.message.role) {
      case "user":
        return "text-blue-400"
      case "assistant":
        return "text-green-400"
      case "thought":
        return "text-yellow-400 italic"
    }
  }

  return (
    <div data-testid="acp-message" data-role={props.message.role} class={bubbleClass()}>
      <div class={`text-xs font-medium mb-1 ${labelClass()}`}>
        {roleLabel()}
      </div>
      <Show
        when={props.message.role !== "user"}
        fallback={
          <div class="text-sm whitespace-pre-wrap break-words">
            {props.message.text}
          </div>
        }
      >
        <Markdown
          text={props.message.text}
          class="text-sm break-words prose prose-invert prose-sm max-w-none"
        />
      </Show>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Tool call card
// ---------------------------------------------------------------------------

/** Map ACP tool kind to an appropriate icon name for BasicTool. */
function toolKindIcon(kind?: string): string {
  switch (kind) {
    case "read": return "glasses"
    case "edit": return "code-lines"
    case "delete": return "trash"
    case "move": return "arrow-right"
    case "search": return "magnifying-glass"
    case "execute": return "console"
    case "think": return "brain"
    case "fetch": return "link"
    case "switch_mode": return "arrow-right"
    default: return "mcp"
  }
}

function ToolCallCard(props: {
  toolCall: ToolCall
  pendingPermission?: PermissionRequest
  onRespondPermission?: (requestId: number | string, optionId: string) => void
}) {
  const tc = () => props.toolCall
  return (
    <div data-testid="tool-call-card">
      <BasicTool
        icon={toolKindIcon(tc().kind)}
        trigger={{
          title: tc().title,
          subtitle: tc().kind ?? "tool",
        }}
        defaultOpen={false}
        forceOpen={!!props.pendingPermission}
      >
        <Show when={tc().content && tc().content!.length > 0}>
          <div class="space-y-2">
            <For each={tc().content}>
              {(item) => {
                if (item.type === "diff") {
                  const diffItem = item as ToolCallDiff
                  return (
                    <Diff
                      before={{ name: diffItem.path, contents: diffItem.oldText ?? "" }}
                      after={{ name: diffItem.path, contents: diffItem.newText }}
                    />
                  )
                }
                if (item.type === "content" && item.content.type === "text") {
                  return (
                    <div data-component="tool-output" data-scrollable class="max-h-64 overflow-y-auto">
                      <Markdown text={item.content.text} class="text-xs" />
                    </div>
                  )
                }
                if (item.type === "terminal") {
                  return (
                    <div class="text-xs opacity-60 font-mono">
                      Terminal: {(item as { terminalId: string }).terminalId}
                    </div>
                  )
                }
                return null
              }}
            </For>
          </div>
        </Show>
        <Show when={tc().rawOutput}>
          <div data-component="tool-output" data-scrollable class="max-h-64 overflow-y-auto mt-2">
            <Markdown text={`\`\`\`json\n${JSON.stringify(tc().rawOutput, null, 2)}\n\`\`\``} class="text-xs" />
          </div>
        </Show>
      </BasicTool>

      {/* Inline permission prompt */}
      <Show when={props.pendingPermission}>
        {(perm) => (
          <div class="mt-1 rounded-md border border-amber-700 bg-[rgba(217,119,6,0.08)] px-3 py-2 text-xs">
            <div class="font-medium mb-1.5">Permission required</div>
            <div class="flex gap-2 flex-wrap">
              <For each={perm().options}>
                {(opt) => {
                  const isAllow = opt.kind === "allow_once" || opt.kind === "allow_always"
                  return (
                    <button
                      type="button"
                      data-testid={`perm-option-${opt.kind}`}
                      class="px-2.5 py-1 rounded text-xs font-medium cursor-pointer border transition-colors"
                      classList={{
                        "bg-green-900 border-green-700 text-green-300 hover:bg-green-800": isAllow,
                        "bg-red-900 border-red-700 text-red-300 hover:bg-red-800": !isAllow,
                      }}
                      onClick={() => props.onRespondPermission?.(perm().requestId, opt.optionId)}
                    >
                      {opt.name}
                    </button>
                  )
                }}
              </For>
            </div>
          </div>
        )}
      </Show>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Permission request card
// ---------------------------------------------------------------------------

/** Standalone permission card for orphan permissions not associated with a visible tool call. */
function PermissionCard(props: {
  request: PermissionRequest
  onRespond: (requestId: number | string, optionId: string) => void
}) {
  const req = () => props.request

  return (
    <div
      data-testid="permission-card"
      class="rounded-md border border-amber-700 bg-[rgba(217,119,6,0.08)] px-3 py-2 text-xs"
    >
      <div class="font-medium mb-1">Permission Request</div>
      <div class="mb-2 opacity-80">
        Tool: {req().toolCall.title ?? req().toolCall.toolCallId}
      </div>
      <div class="flex gap-2 flex-wrap">
        <For each={req().options}>
          {(opt) => {
            const isAllow =
              opt.kind === "allow_once" || opt.kind === "allow_always"
            return (
              <button
                type="button"
                data-testid={`perm-option-${opt.kind}`}
                class="px-2.5 py-1 rounded text-xs font-medium cursor-pointer border transition-colors"
                classList={{
                  "bg-green-900 border-green-700 text-green-300 hover:bg-green-800":
                    isAllow,
                  "bg-red-900 border-red-700 text-red-300 hover:bg-red-800":
                    !isAllow,
                }}
                onClick={() =>
                  props.onRespond(req().requestId, opt.optionId)
                }
              >
                {opt.name}
              </button>
            )
          }}
        </For>
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Plan display
// ---------------------------------------------------------------------------

function PlanDisplay(props: { entries: PlanEntry[] }) {
  return (
    <Show when={props.entries.length > 0}>
      <div class="rounded-md border border-border-base px-3 py-2 text-xs" data-testid="plan-display">
        <div class="font-medium mb-1.5 text-text-strong">Plan</div>
        <div class="space-y-1">
          <For each={props.entries}>
            {(entry) => {
              const statusIcon = () => {
                switch (entry.status) {
                  case "completed": return "✓"
                  case "in_progress": return "●"
                  case "pending": return "○"
                  default: return "○"
                }
              }
              const statusColor = () => {
                switch (entry.status) {
                  case "completed": return "text-green-400"
                  case "in_progress": return "text-yellow-400"
                  default: return "text-text-weak"
                }
              }
              return (
                <div class="flex items-start gap-2">
                  <span class={`font-mono ${statusColor()} shrink-0`}>{statusIcon()}</span>
                  <span classList={{ "line-through opacity-50": entry.status === "completed" }}>
                    {entry.content}
                  </span>
                </div>
              )
            }}
          </For>
        </div>
      </div>
    </Show>
  )
}

// ---------------------------------------------------------------------------
// Prompt input bar
// ---------------------------------------------------------------------------

function PromptBar(props: {
  sessionId?: string
  onSend: (text: string) => void
  onCancel: () => void
  prompting: boolean
  disabled: boolean
  availableCommands?: Array<{ name: string; description: string }>
}) {
  const [text, setText] = createSignal("")
  const [showSlashMenu, setShowSlashMenu] = createSignal(false)
  const [selectedSlashIdx, setSelectedSlashIdx] = createSignal(0)
  let textareaRef: HTMLTextAreaElement | undefined

  // Prompt history -- persisted to localStorage so it survives page refresh.
  const historyKey = `devaipod-prompt-history-${props.sessionId ?? "default"}`
  const promptHistory: string[] = (() => {
    try { return JSON.parse(localStorage.getItem(historyKey) || "[]") }
    catch { return [] }
  })()
  let historyIdx = -1
  let draftText = ""  // Preserves what was typed before entering history

  function saveHistory() {
    try {
      // Keep last 100 entries.
      localStorage.setItem(historyKey, JSON.stringify(promptHistory.slice(0, 100)))
    } catch { /* ignore */ }
  }

  const filteredCommands = createMemo(() => {
    if (!showSlashMenu() || !props.availableCommands) return []
    const input = text().slice(1).toLowerCase() // Remove leading /
    return props.availableCommands.filter((cmd) =>
      cmd.name.toLowerCase().includes(input)
    )
  })

  function autoResize() {
    if (textareaRef) {
      textareaRef.style.height = "auto"
      textareaRef.style.height = Math.min(textareaRef.scrollHeight, 200) + "px"
    }
  }

  function handleSubmit(e?: Event) {
    e?.preventDefault()
    const val = text().trim()
    if (!val) return
    promptHistory.unshift(val)
    historyIdx = -1
    draftText = ""
    saveHistory()
    props.onSend(val)
    setText("")
    setShowSlashMenu(false)
    if (textareaRef) {
      textareaRef.style.height = "auto"
    }
  }

  function handleInput(e: InputEvent) {
    const val = (e.currentTarget as HTMLTextAreaElement).value
    setText(val)
    // Show slash command menu when text starts with /
    if (val.startsWith("/") && !val.includes(" ")) {
      setShowSlashMenu(true)
      setSelectedSlashIdx(0)
    } else {
      setShowSlashMenu(false)
    }
    autoResize()
  }

  function handleKeyDown(e: KeyboardEvent) {
    if (showSlashMenu() && filteredCommands().length > 0) {
      if (e.key === "ArrowDown") {
        e.preventDefault()
        setSelectedSlashIdx((idx) => Math.min(idx + 1, filteredCommands().length - 1))
        return
      }
      if (e.key === "ArrowUp") {
        e.preventDefault()
        setSelectedSlashIdx((idx) => Math.max(idx - 1, 0))
        return
      }
      if (e.key === "Enter" || e.key === "Tab") {
        e.preventDefault()
        const cmd = filteredCommands()[selectedSlashIdx()]
        if (cmd) {
          setText(cmd.name + " ")
          setShowSlashMenu(false)
        }
        return
      }
      if (e.key === "Escape") {
        setShowSlashMenu(false)
        return
      }
    }

    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault()
      handleSubmit()
      return
    }
    // Prompt history navigation (only when cursor at start/end)
    if (e.key === "ArrowUp" && promptHistory.length > 0) {
      const textarea = e.currentTarget as HTMLTextAreaElement
      if (textarea.selectionStart === 0 && textarea.selectionEnd === 0) {
        e.preventDefault()
        // Save draft before entering history
        if (historyIdx === -1) {
          draftText = text()
        }
        historyIdx = Math.min(historyIdx + 1, promptHistory.length - 1)
        setText(promptHistory[historyIdx])
        requestAnimationFrame(autoResize)
      }
    }
    if (e.key === "ArrowDown" && historyIdx >= 0) {
      e.preventDefault()
      historyIdx--
      if (historyIdx >= 0) {
        setText(promptHistory[historyIdx])
      } else {
        // Back to draft
        setText(draftText)
      }
      requestAnimationFrame(autoResize)
    }
  }

  function selectSlashCommand(cmd: { name: string }) {
    setText(cmd.name + " ")
    setShowSlashMenu(false)
    textareaRef?.focus()
  }

  return (
    <div class="relative border-t border-border-base shrink-0" data-testid="prompt-bar">
      {/* Slash command menu */}
      <Show when={showSlashMenu() && filteredCommands().length > 0}>
        <div
          class="absolute bottom-full left-3 right-3 mb-1 border border-border-base rounded-md max-h-48 overflow-y-auto z-10"
          style={{ "background-color": "#2a2323", "box-shadow": "0 8px 24px rgba(0,0,0,0.5)" }}
        >
          <For each={filteredCommands()}>
            {(cmd, idx) => (
              <button
                type="button"
                class="w-full text-left px-3 py-1.5 text-sm hover:bg-fill-element-base transition-colors cursor-pointer"
                classList={{ "bg-fill-element-base": idx() === selectedSlashIdx() }}
                onMouseDown={(e) => {
                  e.preventDefault()
                  selectSlashCommand(cmd)
                }}
              >
                <span class="font-mono text-blue-400">{cmd.name}</span>
                <span class="ml-2 opacity-60">{cmd.description}</span>
              </button>
            )}
          </For>
        </div>
      </Show>

      <form
        onSubmit={handleSubmit}
        class="flex items-end gap-2 px-3 py-2"
      >
        <textarea
          ref={textareaRef}
          data-testid="prompt-input"
          class="flex-1 bg-fill-element-base border border-border-base rounded-md px-3 py-2 text-sm text-text-strong outline-none focus:border-blue-500 transition-colors resize-none min-h-[38px] max-h-[200px]"
          placeholder={
            props.disabled
              ? "Connecting..."
              : "Type a message... (Shift+Enter for newline, / for commands)"
          }
          disabled={props.disabled}
          value={text()}
          onInput={handleInput}
          onKeyDown={handleKeyDown}
          rows={1}
        />
        <Show
          when={!props.prompting}
          fallback={
            <button
              type="button"
              data-testid="cancel-btn"
              class="px-3.5 py-2 rounded-md text-sm font-medium cursor-pointer border border-red-700 bg-red-900 text-red-300 hover:bg-red-800 transition-colors"
              onClick={props.onCancel}
            >
              Cancel
            </button>
          }
        >
          <button
            type="submit"
            data-testid="send-btn"
            class="px-3.5 py-2 rounded-md text-sm font-medium cursor-pointer border border-blue-700 bg-blue-900 text-blue-300 hover:bg-blue-800 transition-colors disabled:opacity-30 disabled:cursor-default"
            disabled={props.disabled || !text().trim()}
          >
            Send
          </button>
        </Show>
      </form>
    </div>
  )
}

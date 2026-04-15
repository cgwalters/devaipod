import {
  createEffect,
  createMemo,
  createSignal,
  For,
  Index,
  Match,
  onCleanup,
  onMount,
  Show,
  Switch,
} from "solid-js"
import { createStore } from "solid-js/store"
import { Button } from "@opencode-ai/ui/button"
import { IconButton } from "@opencode-ai/ui/icon-button"
import { Icon } from "@opencode-ai/ui/icon"
import { Card } from "@opencode-ai/ui/card"
import { Tag } from "@opencode-ai/ui/tag"
import { TextField } from "@opencode-ai/ui/text-field"
import { Collapsible } from "@opencode-ai/ui/collapsible"
import { Checkbox } from "@opencode-ai/ui/checkbox"
import { Switch as SwitchToggle } from "@opencode-ai/ui/switch"
import { Spinner } from "@opencode-ai/ui/spinner"
import {
  DevaipodProvider,
  useDevaipod,
  type PodInfo,
  type DevcontainerPod,
  type Proposal,
  type LaunchWorkspaceParams,
  type GatorScopeConfig,
  type GatorScopesResponse,
  type ControlPlaneRepo,
  type ControlPlaneAgent,
  type ControlPlaneDevcontainer,
  frecencySortPods,
  effectiveTimestamp,
  type SortBy,
  type GroupBy,
  type Density,
  sortPods,
  groupPods,
} from "@/context/devaipod"
import { apiFetch } from "@/utils/devaipod-api"

// ---------------------------------------------------------------------------
// Diff types (from GET /api/devaipod/pods/{name}/diff)
// ---------------------------------------------------------------------------

interface DiffCommit {
  sha: string
  message: string
  author: string
  timestamp: string
}

interface DiffResponse {
  branch: string
  commit_count: number
  commits: DiffCommit[]
  diff: string
  is_stat: boolean
}

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

type PodFilter = "all" | "running" | "stopped" | "done"

// ---------------------------------------------------------------------------
// Search query parser
// ---------------------------------------------------------------------------

interface ParsedQuery {
  repo?: string
  task?: string
  status?: PodFilter
  freeText: string[]
}

function parseSearchQuery(raw: string): ParsedQuery {
  const result: ParsedQuery = { freeText: [] }
  // Match structured terms: key:"quoted value" or key:value
  const regex = /(\w+):(?:"([^"]*)"|([\S]+))/g
  let lastIndex = 0
  let match: RegExpExecArray | null

  // Collect positions of structured matches to extract free text from gaps
  const gaps: string[] = []
  // eslint-disable-next-line no-cond-assign
  while ((match = regex.exec(raw)) !== null) {
    if (match.index > lastIndex) {
      gaps.push(raw.slice(lastIndex, match.index))
    }
    lastIndex = match.index + match[0].length

    const key = match[1].toLowerCase()
    const value = match[2] ?? match[3]

    if (key === "repo") result.repo = value
    else if (key === "task") result.task = value
    else if (key === "status") {
      const v = value.toLowerCase()
      if (v === "running" || v === "stopped" || v === "done") result.status = v
    }
  }

  if (lastIndex < raw.length) {
    gaps.push(raw.slice(lastIndex))
  }

  const freeText = gaps.join(" ").trim()
  if (freeText) {
    result.freeText = freeText.toLowerCase().split(/\s+/).filter(Boolean)
  }

  return result
}

function podMatchesQuery(
  pod: PodInfo,
  query: ParsedQuery,
  isDone: boolean,
  isRunning: boolean,
  agentTitle?: string,
): boolean {
  const labels = pod.Labels ?? {}
  const repo = labels["io.devaipod.repo"] ?? ""
  const task = labels["io.devaipod.task"] ?? ""
  const title = agentTitle || labels["io.devaipod.title"] || ""
  const shortName = pod.Name.replace("devaipod-", "")

  if (query.repo && !repo.toLowerCase().includes(query.repo.toLowerCase())) return false
  if (query.task && !task.toLowerCase().includes(query.task.toLowerCase())) return false

  if (query.status) {
    if (query.status === "done" && !isDone) return false
    if (query.status === "running" && (!isRunning || isDone)) return false
    if (query.status === "stopped" && (isRunning || isDone)) return false
  }

  for (const term of query.freeText) {
    const haystack = `${shortName} ${repo} ${task} ${title} ${pod.Name}`.toLowerCase()
    if (!haystack.includes(term)) return false
  }

  return true
}

// ---------------------------------------------------------------------------
// View preferences (localStorage persistence)
// ---------------------------------------------------------------------------

interface ViewPrefs {
  sortBy: SortBy
  groupBy: GroupBy
  density: Density
}

const VIEW_PREFS_KEY = "devaipod-view-prefs"

function loadViewPrefs(): ViewPrefs {
  try {
    const raw = localStorage.getItem(VIEW_PREFS_KEY)
    if (raw) {
      const parsed = JSON.parse(raw)
      return {
        sortBy: (["activity", "repo", "created"] as SortBy[]).includes(parsed.sortBy) ? parsed.sortBy : "activity",
        groupBy: (["time", "repo", "status", "none"] as GroupBy[]).includes(parsed.groupBy) ? parsed.groupBy : "time",
        density: (["comfortable", "compact"] as Density[]).includes(parsed.density) ? parsed.density : "comfortable",
      }
    }
  } catch {
    // ignore
  }
  return { sortBy: "activity", groupBy: "time", density: "comfortable" }
}

function saveViewPrefs(prefs: ViewPrefs) {
  try {
    localStorage.setItem(VIEW_PREFS_KEY, JSON.stringify(prefs))
  } catch {
    // ignore
  }
}

// ---------------------------------------------------------------------------
// View toolbar (sort / group / density controls)
// ---------------------------------------------------------------------------

function ViewToolbar(props: {
  sortBy: SortBy
  groupBy: GroupBy
  density: Density
  onSortChange: (s: SortBy) => void
  onGroupChange: (g: GroupBy) => void
  onDensityChange: (d: Density) => void
}) {
  const chipClass = (active: boolean) =>
    active
      ? "bg-fill-element-active text-text-strong"
      : "text-text-weak hover:text-text-secondary-base hover:bg-fill-element-base"

  return (
    <div class="flex flex-wrap items-center gap-x-4 gap-y-2 mb-4">
      {/* Sort controls */}
      <div class="flex items-center gap-1">
        <span class="text-11-regular text-text-weak mr-1">Sort:</span>
        <For each={[
          ["activity", "Activity"],
          ["repo", "Repo"],
          ["created", "Created"],
        ] as [SortBy, string][]}>
          {([value, label]) => (
            <button
              type="button"
              class="px-2 py-0.5 rounded text-11-regular transition-colors cursor-pointer"
              classList={{ [chipClass(props.sortBy === value)]: true }}
              onClick={() => props.onSortChange(value)}
            >
              {label}
            </button>
          )}
        </For>
      </div>

      {/* Group controls */}
      <div class="flex items-center gap-1">
        <span class="text-11-regular text-text-weak mr-1">Group:</span>
        <For each={[
          ["time", "Time"],
          ["repo", "Repo"],
          ["status", "Status"],
          ["none", "None"],
        ] as [GroupBy, string][]}>
          {([value, label]) => (
            <button
              type="button"
              class="px-2 py-0.5 rounded text-11-regular transition-colors cursor-pointer"
              classList={{ [chipClass(props.groupBy === value)]: true }}
              onClick={() => props.onGroupChange(value)}
            >
              {label}
            </button>
          )}
        </For>
      </div>

      {/* Density toggle */}
      <div class="flex items-center gap-1 ml-auto">
        <button
          type="button"
          class="px-1.5 py-0.5 rounded text-11-regular transition-colors cursor-pointer"
          classList={{ [chipClass(props.density === "comfortable")]: true }}
          onClick={() => props.onDensityChange("comfortable")}
          title="Comfortable view"
          aria-label="Comfortable density"
        >
          {"\u2630"}
        </button>
        <button
          type="button"
          class="px-1.5 py-0.5 rounded text-11-regular transition-colors cursor-pointer"
          classList={{ [chipClass(props.density === "compact")]: true }}
          onClick={() => props.onDensityChange("compact")}
          title="Compact view"
          aria-label="Compact density"
        >
          {"\u229E"}
        </button>
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Compact pod card (single-line density)
// ---------------------------------------------------------------------------

function CompactPodCard(props: {
  pod: PodInfo
  focused: boolean
  onFocus: () => void
  hideRepo?: boolean
}) {
  const ctx = useDevaipod()

  const shortName = () => props.pod.Name.replace("devaipod-", "")
  const isRunning = () => (props.pod.Status ?? "").toLowerCase() === "running"
  const labels = () => props.pod.Labels ?? {}
  const repo = () => labels()["io.devaipod.repo"] ?? ""
  const agentStatus = () => ctx.agentStatus[props.pod.Name]
  const title = () => agentStatus()?.title || labels()["io.devaipod.title"] || shortName()
  const isDone = () => agentStatus()?.completion_status === "done"

  const statusDot = createMemo(() => {
    if (!isRunning()) return { char: "\u25CC", cls: "text-text-weak" }
    if (isDone()) return { char: "\u25C6", cls: "text-violet-400" }
    const activity = agentStatus()?.activity
    if (activity === "Working") return { char: "\u25CF", cls: "text-icon-success-base" }
    if (activity === "Idle") return { char: "\u25CB", cls: "text-icon-info-base" }
    return { char: "\u2026", cls: "text-text-weak" }
  })

  const activityText = createMemo(() => {
    if (!isRunning()) return ""
    const s = agentStatus()
    if (!s) return ""
    if (s.current_tool) return `\u2192 ${s.current_tool}`
    if (s.status_line) return s.status_line
    return ""
  })

  const relativeTime = createMemo(() => {
    const ts = effectiveTimestamp(props.pod)
    if (!ts) return ""
    const diff = Date.now() - ts
    if (diff < 0 || diff < 60_000) return "just now"
    if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}m ago`
    if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}h ago`
    return `${Math.floor(diff / 86_400_000)}d ago`
  })

  const repoShort = createMemo(() => {
    const r = repo()
    if (!r) return ""
    const parts = r.split("/")
    return parts[parts.length - 1]
  })

  let rowRef: HTMLDivElement | undefined

  createEffect(() => {
    if (props.focused && rowRef) {
      rowRef.focus({ preventScroll: true })
    }
  })

  return (
    <div
      ref={rowRef}
      tabIndex={0}
      onFocus={props.onFocus}
      class="flex items-center gap-2 px-3 py-2 rounded border border-border-base bg-background-base transition-colors cursor-pointer hover:bg-fill-element-base"
      classList={{
        "ring-2 ring-border-active-base": props.focused,
        "opacity-50": !isRunning() && !isDone(),
        "opacity-70": isDone(),
      }}
      onClick={() => {
        if (isRunning()) {
          ctx.openPod(props.pod.Name).catch(alertError)
        } else {
          ctx.startPod(props.pod.Name).catch(alertError)
        }
      }}
    >
      <span class="text-14-medium shrink-0" classList={{ [statusDot().cls]: true }}>
        {statusDot().char}
      </span>

      <span class="text-12-regular text-text-strong truncate min-w-0 flex-1" title={title()}>
        {title()}
      </span>

      <Show when={!props.hideRepo && repoShort()}>
        <span class="text-10-regular text-text-weak bg-fill-element-base px-1.5 py-0.5 rounded shrink-0 max-w-[120px] truncate">
          {repoShort()}
        </span>
      </Show>

      <Show when={activityText()}>
        <span class="text-11-regular text-text-weak truncate max-w-[160px] shrink-0">
          {activityText()}
        </span>
      </Show>

      <span class="text-11-regular text-text-weak shrink-0">
        {relativeTime()}
      </span>

      <Button
        variant={isRunning() ? "primary" : "secondary"}
        size="small"
        onClick={(e: MouseEvent) => {
          e.stopPropagation()
          if (isRunning()) {
            ctx.openPod(props.pod.Name).catch(alertError)
          } else {
            ctx.startPod(props.pod.Name).catch(alertError)
          }
        }}
      >
        {isRunning() ? "Open" : "Start"}
      </Button>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Main content
// ---------------------------------------------------------------------------

function PodsPageContent() {
  const ctx = useDevaipod()

  const [showForm, setShowForm] = createSignal(false)
  const [focusedIdx, setFocusedIdx] = createSignal(-1)
  const [searchText, setSearchText] = createSignal("")
  const [prefillSource, setPrefillSource] = createSignal("")

  // Ref for the launch form area so we can scroll to it
  let launchRef: HTMLDivElement | undefined

  // View preference state (createStore per project convention)
  const [viewPrefs, setViewPrefs] = createStore<ViewPrefs>(loadViewPrefs())

  // Persist preference changes
  createEffect(() => {
    saveViewPrefs({ sortBy: viewPrefs.sortBy, groupBy: viewPrefs.groupBy, density: viewPrefs.density })
  })

  // Derive completion status for a pod from agent status
  const podCompletionStatus = (podName: string) =>
    ctx.agentStatus[podName]?.completion_status ?? "active"

  const isPodRunning = (pod: PodInfo) =>
    (pod.Status ?? "").toLowerCase() === "running"

  const isPodDone = (podName: string) =>
    podCompletionStatus(podName) === "done"

  // Sorted, then filtered pods
  const filteredPods = createMemo(() => {
    const sorted = sortPods(ctx.pods, viewPrefs.sortBy)
    const raw = searchText().trim()
    if (!raw) return sorted
    const query = parseSearchQuery(raw)
    return sorted.filter((p) =>
      podMatchesQuery(p, query, isPodDone(p.Name), isPodRunning(p), ctx.agentStatus[p.Name]?.title)
    )
  })

  // Group filtered pods into labeled sections
  const groupedPods = createMemo(() => {
    return groupPods(
      filteredPods(),
      viewPrefs.groupBy,
      (name) => ctx.agentStatus[name],
    )
  })

  // Show dividers when there are multiple groups. For non-time groupings,
  // also show a divider for a single named group (e.g., one "Working" section).
  // For time grouping, match the original behavior: dividers only with 2+ sections.
  const showDividers = createMemo(() => {
    const groups = groupedPods()
    if (groups.length > 1) return true
    if (groups.length === 1 && groups[0].label !== "" && viewPrefs.groupBy !== "time") return true
    return false
  })

  // Filter counts for the filter chips
  const filterCounts = createMemo(() => {
    const pods = ctx.pods
    let running = 0, stopped = 0, done = 0
    for (const p of pods) {
      if (isPodDone(p.Name)) done++
      else if (isPodRunning(p)) running++
      else stopped++
    }
    return { all: pods.length, running, stopped, done }
  })

  // Alias for keyboard navigation
  const flatPodList = filteredPods

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
        const total = flatPodList().length
        if (total === 0) return
        e.preventDefault()
        setFocusedIdx((prev) => {
          if (e.key === "ArrowDown") return prev < 0 ? 0 : Math.min(prev + 1, total - 1)
          return prev < 0 ? total - 1 : Math.max(prev - 1, 0)
        })
      }

      if (e.key === "Enter" && !isInput) {
        const idx = focusedIdx()
        const cards = flatPodList()
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

  // Quick filter chip handler — inserts/replaces status: prefix in search
  function applyStatusFilter(status: PodFilter) {
    const current = searchText()
    // Remove any existing status: term
    const withoutStatus = current.replace(/\bstatus:\S+/g, "").trim()
    if (status === "all") {
      setSearchText(withoutStatus)
    } else {
      setSearchText(withoutStatus ? `${withoutStatus} status:${status}` : `status:${status}`)
    }
  }

  // Track which status filter chip is active based on search text
  const activeStatusFilter = createMemo((): PodFilter => {
    const query = parseSearchQuery(searchText())
    return query.status ?? "all"
  })

  // Compute a flat index offset for each group so we can map
  // group-local indexes to the flat focused index
  function flatIndexOffset(sectionIdx: number): number {
    let offset = 0
    const groups = groupedPods()
    for (let i = 0; i < sectionIdx; i++) {
      offset += groups[i].pods.length
    }
    return offset
  }

  // Quick-launch from a repo section: scroll to and open the launch form
  function quickLaunchForRepo(repoLabel: string) {
    // Try to find a recent source matching this repo label
    const match = ctx.recentSources.find((rs) =>
      rs.source.toLowerCase().includes(repoLabel.toLowerCase()),
    )
    setPrefillSource(match?.source ?? repoLabel)
    setShowForm(true)
    // Scroll to the launch form
    setTimeout(() => launchRef?.scrollIntoView({ behavior: "smooth", block: "start" }), 50)
  }

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
      <div class="mb-6" ref={launchRef}>
        <Show
          when={showForm()}
          fallback={
            <Button variant="primary" icon="plus" onClick={() => setShowForm(true)}>
              New Workspace
            </Button>
          }
        >
          <LaunchForm onClose={() => setShowForm(false)} prefillSource={prefillSource()} />
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

      {/* Control plane repo-grouped view — primary content */}
      <ControlPlaneView onQuickLaunch={quickLaunchForRepo} />

      {/* Empty state when no data at all */}
      <Show when={ctx.pods.length === 0 && ctx.controlPlane.length === 0 && pendingLaunches().length === 0}>
        <Show when={ctx.connected !== undefined}>
          <div class="flex flex-col items-center justify-center py-12 text-text-weak">
            <div class="mb-3 opacity-30">
              <Icon name="server" size="large" />
            </div>
            <p class="text-14-medium mb-1">No workspaces found</p>
            <p class="text-12-regular">Launch one with the button above</p>
          </div>
        </Show>
      </Show>

      {/* All Pods — collapsible flat list for power users */}
      <Show when={ctx.pods.length > 0}>
        <div class="mt-8">
          <Collapsible variant="ghost">
            <Collapsible.Trigger class="flex items-center gap-2 text-13-regular text-text-weak cursor-pointer hover:text-text-secondary-base transition-colors">
              <Collapsible.Arrow />
              All Pods ({ctx.pods.length})
            </Collapsible.Trigger>
            <Collapsible.Content class="mt-3">
              {/* Search bar and filter chips */}
              <div class="mb-4 flex flex-col gap-2">
                <input
                  type="text"
                  placeholder="Search pods... (repo:name, task:text, status:running)"
                  class="w-full text-12-regular bg-background-base border border-border-base rounded px-3 py-2 text-text-strong placeholder:text-text-weak focus:outline-none focus:border-border-active-base"
                  value={searchText()}
                  onInput={(e) => setSearchText(e.currentTarget.value)}
                />
                <div class="flex gap-1">
                  <For each={["all", "running", "stopped", "done"] as PodFilter[]}>
                    {(f) => {
                      const count = () => filterCounts()[f]
                      return (
                        <button
                          type="button"
                          class="px-2.5 py-1 rounded text-12-regular transition-colors cursor-pointer"
                          classList={{
                            "bg-fill-element-active text-text-strong": activeStatusFilter() === f,
                            "text-text-weak hover:text-text-secondary-base hover:bg-fill-element-base": activeStatusFilter() !== f,
                          }}
                          onClick={() => applyStatusFilter(f)}
                        >
                          {f.charAt(0).toUpperCase() + f.slice(1)}
                          <span class="ml-1 opacity-60">{count()}</span>
                        </button>
                      )
                    }}
                  </For>
                </div>
              </div>

              <ViewToolbar
                sortBy={viewPrefs.sortBy}
                groupBy={viewPrefs.groupBy}
                density={viewPrefs.density}
                onSortChange={(s) => setViewPrefs("sortBy", s)}
                onGroupChange={(g) => setViewPrefs("groupBy", g)}
                onDensityChange={(d) => setViewPrefs("density", d)}
              />

              <Show
                when={filteredPods().length > 0}
                fallback={
                  <div class="flex flex-col items-center justify-center py-8 text-text-weak">
                    <p class="text-12-regular">
                      {searchText().trim() ? "No matching workspaces" : "No workspaces"}
                    </p>
                  </div>
                }
              >
                <div class="flex flex-col gap-3">
                  <For each={groupedPods()}>
                    {(group, groupIdx) => {
                      const offset = () => flatIndexOffset(groupIdx())
                      return (
                        <>
                          <Show when={showDividers() && group.label}>
                            <div class="flex items-center gap-3 my-2">
                              <hr class="flex-1 border-t border-border-base" />
                              <span class="text-11-regular text-text-weak shrink-0">
                                {group.label}
                                <Show when={group.pods.length > 1}>
                                  <span class="ml-1 opacity-60">({group.pods.length})</span>
                                </Show>
                              </span>
                              <hr class="flex-1 border-t border-border-base" />
                            </div>
                          </Show>
                          <For each={group.pods}>
                            {(pod, podIdx) => (
                              <Show
                                when={viewPrefs.density === "compact"}
                                fallback={
                                  <PodCard
                                    pod={pod}
                                    focused={focusedIdx() === offset() + podIdx()}
                                    onFocus={() => setFocusedIdx(offset() + podIdx())}
                                  />
                                }
                              >
                                <CompactPodCard
                                  pod={pod}
                                  focused={focusedIdx() === offset() + podIdx()}
                                  onFocus={() => setFocusedIdx(offset() + podIdx())}
                                  hideRepo={viewPrefs.groupBy === "repo"}
                                />
                              </Show>
                            )}
                          </For>
                        </>
                      )
                    }}
                  </For>
                </div>
              </Show>
            </Collapsible.Content>
          </Collapsible>
        </div>
      </Show>

      {/* Devcontainers section */}
      <DevcontainerSection />
    </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Control Plane — repo-grouped view
// ---------------------------------------------------------------------------

/** Format an ISO timestamp as a relative "time ago" string. */
function timeAgo(iso: string): string {
  const ts = new Date(iso).getTime()
  if (Number.isNaN(ts)) return ""
  const age = Date.now() - ts
  if (age < 60_000) return "just now"
  const mins = Math.floor(age / 60_000)
  if (mins < 60) return `${mins}m ago`
  const hours = Math.floor(mins / 60)
  if (hours < 24) return `${hours}h ago`
  const days = Math.floor(hours / 24)
  if (days === 1) return "1d ago"
  return `${days}d ago`
}

function ControlPlaneView(props: { onQuickLaunch: (repoLabel: string) => void }) {
  const ctx = useDevaipod()
  const [showInactive, setShowInactive] = createSignal(true)

  const activeRepos = createMemo(() =>
    ctx.controlPlane.filter((r) => r.active_count > 0),
  )
  const inactiveRepos = createMemo(() =>
    ctx.controlPlane.filter((r) => r.active_count === 0),
  )

  return (
    <Show when={ctx.controlPlane.length > 0}>
      <div class="mb-8">
        <h2 class="text-16-medium text-text-strong mb-4">Repos</h2>
        <div class="flex flex-col gap-3">
          <For each={activeRepos()}>
            {(repo) => <RepoSection repo={repo} defaultOpen={true} onQuickLaunch={props.onQuickLaunch} />}
          </For>

          <Show when={inactiveRepos().length > 0}>
            <button
              type="button"
              class="flex items-center gap-2 text-12-regular text-text-weak hover:text-text-secondary-base transition-colors cursor-pointer py-1"
              onClick={() => setShowInactive((v) => !v)}
            >
              <span class="text-text-weak">{showInactive() ? "\u25BC" : "\u25B8"}</span>
              Inactive repos ({inactiveRepos().length})
            </button>
            <Show when={showInactive()}>
              <For each={inactiveRepos()}>
                {(repo) => <RepoSection repo={repo} defaultOpen={true} onQuickLaunch={props.onQuickLaunch} />}
              </For>
            </Show>
          </Show>
        </div>
      </div>
    </Show>
  )
}

function RepoSection(props: { repo: ControlPlaneRepo; defaultOpen: boolean; onQuickLaunch: (repoLabel: string) => void }) {
  const [open, setOpen] = createSignal(props.defaultOpen)

  // Show last path component for short display, full for title
  const shortRepoName = () => {
    const parts = props.repo.repo.split("/")
    return parts.length > 1 ? parts.slice(-2).join("/") : props.repo.repo
  }

  return (
    <div class="border border-border-base rounded">
      {/* Repo header */}
      <div class="flex items-center">
        <button
          type="button"
          class="flex-1 flex items-center justify-between px-4 py-2.5 hover:bg-surface-secondary transition-colors cursor-pointer min-w-0"
          onClick={() => setOpen((v) => !v)}
        >
          <div class="flex items-center gap-2 min-w-0">
            <span class="text-text-weak text-11-regular">{open() ? "\u25BC" : "\u25B6"}</span>
            <span class="text-13-regular text-text-strong truncate">{shortRepoName()}</span>
          </div>
          <Show when={props.repo.active_count > 0}>
            <span class="text-11-regular text-text-weak bg-fill-element-base px-2 py-0.5 rounded-full">
              {props.repo.active_count} active
            </span>
          </Show>
        </button>
        <button
          type="button"
          class="px-2.5 py-2.5 text-text-weak hover:text-text-strong hover:bg-surface-secondary transition-colors cursor-pointer text-12-regular"
          title={`Launch new workspace for ${shortRepoName()}`}
          onClick={(e) => {
            e.stopPropagation()
            props.onQuickLaunch(props.repo.repo)
          }}
        >
          +
        </button>
      </div>

      {/* Repo body */}
      <Show when={open()}>
        <div class="border-t border-border-base">
          <For each={props.repo.agents}>
            {(agent) => <AgentRow agent={agent} />}
          </For>
          <For each={props.repo.devcontainers}>
            {(dc) => <DevcontainerRow dc={dc} />}
          </For>
          <Show when={props.repo.agents.length === 0 && props.repo.devcontainers.length === 0}>
            <div class="px-4 py-3 text-12-regular text-text-weak">No workspaces</div>
          </Show>
        </div>
      </Show>
    </div>
  )
}

function AgentRow(props: { agent: ControlPlaneAgent }) {
  const ctx = useDevaipod()
  const a = () => props.agent
  const [showDiff, setShowDiff] = createSignal(false)

  const statusDot = createMemo(() => {
    if (a().completion_status === "done") return { char: "\u25C9", cls: "text-violet-400" }
    if (a().is_running) return { char: "\u25CF", cls: "text-icon-success-base" }
    return { char: "\u25CF", cls: "text-text-weak" }
  })

  const displayName = () => a().title || a().short_name
  const statusLabel = () => {
    if (a().title) return a().short_name
    if (a().completion_status === "done") return "Done"
    return a().status
  }

  const lastActive = () => {
    if (a().last_active) return timeAgo(a().last_active!)
    return timeAgo(a().created)
  }

  // Cross-reference with pod-level agent status for activity info
  const podAgentStatus = () => ctx.agentStatus[a().name]
  const activityText = createMemo(() => {
    const s = podAgentStatus()
    if (!s) return null
    if (s.current_tool) return `\u2192 ${s.current_tool}`
    if (s.status_line) return s.status_line
    return s.activity !== "Unknown" ? s.activity : null
  })

  const isDone = () => a().completion_status === "done"

  function navigate() {
    window.location.href = `/agent/${encodeURIComponent(a().name)}/`
  }

  return (
    <div class="border-t border-border-base first:border-t-0">
      <div class="flex items-center gap-3 px-4 py-2 hover:bg-surface-secondary transition-colors">
        {/* Status dot */}
        <span classList={{ [statusDot().cls]: true, "text-11-regular": true }}>{statusDot().char}</span>

        {/* Name + task subtitle */}
        <button
          type="button"
          class="flex-1 min-w-0 text-left cursor-pointer"
          onClick={navigate}
        >
          <div class="flex items-center gap-2">
            <span
              class="text-12-regular truncate"
              classList={{
                "text-text-strong": a().is_running && !isDone(),
                "text-text-weak": !a().is_running || isDone(),
              }}
            >
              {displayName()}
            </span>
            <span class="text-11-regular text-text-weak truncate shrink-0 max-w-[120px]">{statusLabel()}</span>
          </div>
          <Show when={a().task}>
            <div class="text-11-regular text-text-weak truncate mt-0.5">{a().task}</div>
          </Show>
        </button>

        {/* Activity status from pod data */}
        <Show when={activityText() && a().is_running && !isDone()}>
          <span class="text-11-regular text-text-weak truncate shrink-0 max-w-[140px]">{activityText()}</span>
        </Show>

        {/* Time ago */}
        <span class="text-11-regular text-text-weak shrink-0">{lastActive()}</span>

        {/* Diff button for done agents */}
        <Show when={isDone()}>
          <button
            type="button"
            class="text-11-regular text-text-link hover:underline cursor-pointer shrink-0"
            onClick={(e) => {
              e.stopPropagation()
              setShowDiff((v) => !v)
            }}
          >
            {showDiff() ? "hide diff" : "diff"}
          </button>
        </Show>

        {/* Navigate arrow for running agents */}
        <Show when={a().is_running}>
          <span class="text-text-weak text-11-regular shrink-0">{"\u2192"}</span>
        </Show>
      </div>

      {/* Inline diff panel */}
      <Show when={showDiff()}>
        <DiffPanel podName={a().name} />
      </Show>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Diff panel — inline expandable diff viewer
// ---------------------------------------------------------------------------

function DiffPanel(props: { podName: string }) {
  const [diffData, setDiffData] = createSignal<DiffResponse | null>(null)
  const [loading, setLoading] = createSignal(true)
  const [error, setError] = createSignal("")
  const [showFull, setShowFull] = createSignal(false)

  // Fetch diff data. Re-fetch when showFull changes.
  createEffect(() => {
    const stat = !showFull()
    setLoading(true)
    setError("")
    apiFetch<DiffResponse>(
      `/api/devaipod/pods/${encodeURIComponent(props.podName)}/diff?stat=${stat}`,
    )
      .then((data) => setDiffData(data))
      .catch((err) => {
        const msg = err instanceof Error ? err.message : String(err)
        // Gracefully handle 404 (endpoint may not exist yet)
        if (msg.includes("404")) {
          setError("Diff not available for this agent")
        } else {
          setError(msg)
        }
        setDiffData(null)
      })
      .finally(() => setLoading(false))
  })

  return (
    <div class="pl-10 pr-4 py-3 border-l-2 border-border-base ml-4 bg-surface-secondary/30">
      <Show when={loading()}>
        <div class="flex items-center gap-2 text-12-regular text-text-weak">
          <Spinner class="size-3.5" />
          Loading diff...
        </div>
      </Show>

      <Show when={!loading() && error()}>
        <span class="text-11-regular text-text-weak">{error()}</span>
      </Show>

      <Show when={!loading() && diffData()}>
        {(data) => (
          <>
            <div class="text-11-regular text-text-secondary-base mb-1">
              <span class="font-mono">{data().branch}</span>
              <span class="text-text-weak"> — {data().commit_count} commit{data().commit_count !== 1 ? "s" : ""}</span>
            </div>
            <Show when={data().commits.length > 0}>
              <div class="flex flex-col gap-0.5 mb-2">
                <For each={data().commits}>
                  {(commit) => (
                    <div class="text-11-regular text-text-weak">
                      <span class="font-mono text-text-secondary-base">{commit.sha.slice(0, 7)}</span>
                      {" "}{commit.message}
                      <span class="ml-2 opacity-60">{timeAgo(commit.timestamp)}</span>
                    </div>
                  )}
                </For>
              </div>
            </Show>
            <Show when={data().diff}>
              <pre class="text-11-regular mt-1 overflow-x-auto max-h-96 overflow-y-auto bg-surface-secondary p-2 rounded border border-border-base font-mono whitespace-pre-wrap break-all">
                {data().diff}
              </pre>
            </Show>
            <Show when={data().is_stat}>
              <button
                type="button"
                class="text-11-regular text-text-link mt-2 cursor-pointer hover:underline"
                onClick={() => setShowFull(true)}
              >
                Show full diff
              </button>
            </Show>
            <Show when={!data().is_stat && showFull()}>
              <button
                type="button"
                class="text-11-regular text-text-link mt-2 cursor-pointer hover:underline"
                onClick={() => setShowFull(false)}
              >
                Show summary
              </button>
            </Show>
          </>
        )}
      </Show>
    </div>
  )
}

function DevcontainerRow(props: { dc: ControlPlaneDevcontainer }) {
  const dc = () => props.dc

  return (
    <div class="flex items-center gap-3 px-4 py-2 border-t border-border-base first:border-t-0">
      <span class="text-11-regular text-text-weak bg-fill-element-base px-1.5 py-0.5 rounded font-mono">DC</span>
      <span
        class="text-12-regular truncate min-w-0 flex-1"
        classList={{
          "text-text-strong": dc().is_running,
          "text-text-weak": !dc().is_running,
        }}
      >
        {dc().short_name}
      </span>
      <span class="text-11-regular text-text-weak shrink-0">
        {dc().is_running ? "Running" : "Stopped"}
      </span>
      <Show when={dc().is_running}>
        <span class="text-11-regular text-text-weak font-mono shrink-0">ssh {dc().short_name}</span>
      </Show>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Devcontainer section
// ---------------------------------------------------------------------------

function DevcontainerSection() {
  const ctx = useDevaipod()
  const [source, setSource] = createSignal("")
  const [launching, setLaunching] = createSignal(false)
  const [error, setError] = createSignal("")

  const isRunning = (dc: DevcontainerPod) =>
    (dc.status ?? "").toLowerCase() === "running"

  async function handleLaunch(e: Event) {
    e.preventDefault()
    const src = source().trim()
    if (!src) return
    setLaunching(true)
    setError("")
    try {
      await ctx.launchDevcontainer(src)
      setSource("")
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setLaunching(false)
    }
  }

  return (
    <div class="mt-10 pt-6 border-t border-border-base">
      {/* Section header */}
      <div class="flex items-center gap-3 mb-4">
        <h2 class="text-16-medium text-text-strong">Devcontainers</h2>
        <span class="text-11-regular text-text-weak bg-fill-element-base px-2 py-0.5 rounded-full">
          {ctx.devcontainers.length}
        </span>
      </div>

      {/* Launch form */}
      <form onSubmit={handleLaunch} class="flex gap-2 mb-4">
        <input
          type="text"
          placeholder="Path or URL"
          class="flex-1 text-12-regular bg-background-base border border-border-base rounded px-3 py-2 text-text-strong placeholder:text-text-weak focus:outline-none focus:border-border-active-base"
          value={source()}
          onInput={(e) => setSource(e.currentTarget.value)}
          disabled={launching()}
        />
        <Button variant="primary" size="small" type="submit" disabled={launching() || !source().trim()}>
          {launching() ? "Launching..." : "Launch"}
        </Button>
      </form>

      <Show when={error()}>
        <Card variant="error" class="mb-4 p-3">
          <span class="text-12-regular">{error()}</span>
        </Card>
      </Show>

      {/* Devcontainer list */}
      <Show
        when={ctx.devcontainers.length > 0}
        fallback={
          <div class="flex flex-col items-center justify-center py-8 text-text-weak">
            <p class="text-12-regular">No devcontainers</p>
          </div>
        }
      >
        <div class="flex flex-col gap-3">
          <For each={ctx.devcontainers}>
            {(dc) => <DevcontainerCard dc={dc} />}
          </For>
        </div>
      </Show>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Devcontainer card
// ---------------------------------------------------------------------------

function DevcontainerCard(props: { dc: DevcontainerPod }) {
  const ctx = useDevaipod()
  const [actionError, setActionError] = createSignal("")

  const shortName = () => props.dc.name.replace("devaipod-", "")
  const isRunning = () => (props.dc.status ?? "").toLowerCase() === "running"
  const repo = () => props.dc.labels?.["io.devaipod.repo"] ?? ""

  async function withErrorHandling(fn: () => Promise<void>) {
    setActionError("")
    try {
      await fn()
    } catch (err) {
      setActionError(err instanceof Error ? err.message : String(err))
    }
  }

  return (
    <Card class="p-4">
      {/* Header row */}
      <div class="flex items-center justify-between mb-2">
        <div class="flex items-center gap-2 min-w-0">
          <span class="text-14-medium text-text-strong truncate">{shortName()}</span>
        </div>
        <span
          class="text-10-regular uppercase px-1.5 py-0.5 rounded"
          classList={{
            "bg-icon-success-base/20 text-icon-success-base": isRunning(),
            "bg-icon-critical-base/20 text-icon-critical-base": !isRunning(),
          }}
        >
          {isRunning() ? "Running" : "Stopped"}
        </span>
      </div>

      {/* Metadata */}
      <div class="text-12-regular text-text-weak flex flex-col gap-0.5 mb-3">
        <Show when={repo()}>
          <div>
            <span class="text-text-weak">Repo: </span>
            <span class="text-text-secondary-base">{repo()}</span>
          </div>
        </Show>
        <div>
          <span class="text-text-weak">Created: </span>
          <span class="text-text-secondary-base">{formatDate(props.dc.created)}</span>
        </div>
      </div>

      {/* Actions */}
      <div class="flex gap-2 pt-2 border-t border-border-base">
        <Show when={isRunning()}>
          <Button
            variant="secondary"
            size="small"
            onClick={() => withErrorHandling(() => ctx.stopDevcontainer(props.dc.name))}
          >
            Stop
          </Button>
        </Show>
        <Show when={!isRunning()}>
          <Button
            variant="secondary"
            size="small"
            onClick={() => withErrorHandling(() => ctx.startDevcontainer(props.dc.name))}
          >
            Start
          </Button>
        </Show>
        <Button
          variant="ghost"
          size="small"
          class="text-text-critical-base"
          onClick={() => {
            if (confirm(`Delete devcontainer "${shortName()}"? This cannot be undone.`))
              withErrorHandling(() => ctx.deleteDevcontainer(props.dc.name))
          }}
        >
          Delete
        </Button>
        <Show when={isRunning()}>
          <span class="ml-auto text-11-regular text-text-weak font-mono self-center" title="SSH into this devcontainer">
            ssh {shortName()}
          </span>
        </Show>
      </div>

      {/* Action error */}
      <Show when={actionError()}>
        <Card variant="error" class="mt-3 p-2">
          <span class="text-12-regular">{actionError()}</span>
        </Card>
      </Show>
    </Card>
  )
}

// ---------------------------------------------------------------------------
// Launch form
// ---------------------------------------------------------------------------

/** Generate a short title from task text by taking the first ~50 chars at a word boundary. */
function autoTitleFromTask(task: string): string {
  const trimmed = task.trim().replace(/\s+/g, " ")
  if (!trimmed) return ""
  // Take the first sentence or line, whichever is shorter
  const firstLine = trimmed.split(/[.\n]/)[0].trim()
  if (firstLine.length <= 50) return firstLine
  // Truncate at word boundary
  const cut = firstLine.slice(0, 50)
  const lastSpace = cut.lastIndexOf(" ")
  return lastSpace > 20 ? cut.slice(0, lastSpace) : cut
}

function LaunchForm(props: { onClose: () => void; prefillSource?: string }) {
  const ctx = useDevaipod()

  const [repoUrl, setRepoUrl] = createSignal(props.prefillSource ?? "")
  const [task, setTask] = createSignal("")
  const [podName, setPodName] = createSignal("")
  const [imageOverride, setImageOverride] = createSignal("")
  const [scopes, setScopes] = createSignal<string[]>([])
  const [gatorImage, setGatorImage] = createSignal("")
  const [readOnly, setReadOnly] = createSignal(true)
  const [devcontainerJson, setDevcontainerJson] = createSignal("")
  const [useDefaultDevcontainer, setUseDefaultDevcontainer] = createSignal(false)
  const [autoTitle, setAutoTitle] = createSignal(true)
  const [submitting, setSubmitting] = createSignal(false)
  const [error, setError] = createSignal("")

  /** Format a recent-source timestamp as a relative time label. */
  function formatRecent(isoDate: string): string {
    const ts = new Date(isoDate).getTime()
    if (Number.isNaN(ts)) return ""
    const age = Date.now() - ts
    const hours = Math.floor(age / 3_600_000)
    if (hours < 1) return "just now"
    if (hours < 24) return `${hours}h ago`
    const days = Math.floor(hours / 24)
    if (days === 1) return "yesterday"
    if (days < 7) return `${days}d ago`
    if (days < 30) return `${Math.floor(days / 7)}w ago`
    return `${Math.floor(days / 30)}mo ago`
  }

  /** Shorten a path for display: ~/src/foo instead of /home/user/src/foo. */
  function shortenSource(s: string): string {
    // Leave URLs alone
    if (s.startsWith("http://") || s.startsWith("https://") || s.startsWith("git@")) return s
    // Collapse home dir
    const home = "/home/"
    const idx = s.indexOf(home)
    if (idx === 0) {
      const rest = s.slice(home.length)
      const slash = rest.indexOf("/")
      if (slash > 0) return "~" + rest.slice(slash)
    }
    return s
  }

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
      if (useDefaultDevcontainer()) params.use_default_devcontainer = true

      // Auto-generate title from task text if enabled
      if (autoTitle() && t) {
        const generated = autoTitleFromTask(t)
        if (generated) params.title = generated
      }

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
            label="Source"
            placeholder="Local path, repo URL, issue/PR URL"
            value={repoUrl()}
            onChange={setRepoUrl}
            required
          />

          <Show when={ctx.recentSources.length > 0 && !repoUrl().trim()}>
            <div class="flex flex-col gap-1">
              <span class="text-11-regular text-text-weak">Recent</span>
              <div class="flex flex-col">
                <For each={ctx.recentSources.slice(0, 8)}>
                  {(recent) => (
                    <button
                      type="button"
                      class="flex items-center justify-between px-2 py-1.5 rounded text-left hover:bg-surface-hover transition-colors group"
                      onClick={() => setRepoUrl(recent.source)}
                    >
                      <span class="text-12-regular text-text-default truncate mr-3 font-mono">
                        {shortenSource(recent.source)}
                      </span>
                      <span class="text-11-regular text-text-weak opacity-0 group-hover:opacity-100 transition-opacity shrink-0">
                        {formatRecent(recent.last_used)}
                      </span>
                    </button>
                  )}
                </For>
              </div>
            </div>
          </Show>

          <TextField
            label="Task (optional)"
            placeholder="Describe what the agent should work on..."
            value={task()}
            onChange={setTask}
            multiline
          />

          <Checkbox
            checked={autoTitle()}
            onChange={setAutoTitle}
          >
            Auto-generate title from task
            <Show when={autoTitle() && task().trim()}>
              <span class="ml-2 text-text-weak opacity-70">
                — "{autoTitleFromTask(task())}"
              </span>
            </Show>
          </Checkbox>

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

              <Checkbox
                checked={useDefaultDevcontainer()}
                onChange={setUseDefaultDevcontainer}
              >
                Use default devcontainer (from dotfiles repo instead of project's)
              </Checkbox>

              <div>
                <label class="text-12-regular text-text-weak block mb-1">Service-gator scopes</label>
                <p class="text-11-regular text-text-weak opacity-70 mb-2">
                  Control AI agent access to external services (e.g. github:org/repo, github:org/*:write)
                </p>
                <div class="flex flex-col gap-2">
                  <Index each={scopes()}>
                    {(scope, index) => (
                      <div class="flex gap-2 items-center">
                        <TextField
                          hideLabel
                          label="Scope"
                          placeholder="github:org/repo or github:org/*:write"
                          value={scope()}
                          onChange={(v) => updateScope(index, v)}
                          class="flex-1"
                        />
                        <IconButton
                          icon="close-small"
                          size="small"
                          variant="ghost"
                          onClick={() => removeScope(index)}
                        />
                      </div>
                    )}
                  </Index>
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
  const [showSettings, setShowSettings] = createSignal(false)
  const [actionError, setActionError] = createSignal("")
  const [taskExpanded, setTaskExpanded] = createSignal(false)

  const shortName = () => props.pod.Name.replace("devaipod-", "")
  const isAdvisor = () => shortName() === "advisor"
  const isRunning = () => (props.pod.Status ?? "").toLowerCase() === "running"

  const labels = () => props.pod.Labels ?? {}
  const repo = () => labels()["io.devaipod.repo"] ?? ""
  const taskLabel = () => labels()["io.devaipod.task"] ?? ""
  const mode = () => labels()["io.devaipod.mode"] ?? ""

  const agentStatus = () => ctx.agentStatus[props.pod.Name]
  // Title from agent status (pod-api) takes precedence over the creation-time label
  const title = () => agentStatus()?.title || labels()["io.devaipod.title"] || ""
  const isDone = () => agentStatus()?.completion_status === "done"

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
      {/* Header */}
      <div class="w-full flex items-center justify-between p-4">
        <div class="flex items-center gap-2 min-w-0">
          <Show when={title()} fallback={
            <span class="text-14-medium text-text-strong truncate">{shortName()}</span>
          }>
            <span class="text-14-medium text-text-strong truncate" title={title()}>{title()}</span>
            <span class="text-11-regular text-text-weak truncate">{shortName()}</span>
          </Show>
          <IconButton
            icon="copy"
            size="small"
            variant="ghost"
            title="Copy pod name"
            onClick={() => navigator.clipboard.writeText(shortName())}
          />
        </div>
        <div class="flex items-center gap-2">
          <Show when={isDone()}>
            <span class="text-10-regular uppercase px-1.5 py-0.5 rounded bg-violet-500/20 text-violet-400">
              Done
            </span>
          </Show>
          <span
            class="text-10-regular uppercase px-1.5 py-0.5 rounded"
            classList={{ [healthTagClass()]: true }}
          >
            {health().label}
          </span>
          <IconButton
            icon="chevron-down"
            size="small"
            variant="ghost"
            title={collapsed() ? "Expand" : "Collapse"}
            class="transition-transform"
            classList={{ "rotate-[-90deg]": collapsed() }}
            onClick={() => setCollapsed((c) => !c)}
          />
        </div>
      </div>

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
              <Show when={taskLabel().length > 100} fallback={
                <span class="text-text-secondary-base">{taskLabel()}</span>
              }>
                <span class="text-text-secondary-base whitespace-pre-wrap">
                  {taskExpanded() ? taskLabel() : taskLabel().substring(0, 100) + "..."}
                </span>
                <button
                  type="button"
                  class="ml-1 text-text-weak hover:text-text-secondary-base text-11-regular cursor-pointer"
                  onClick={() => setTaskExpanded((v) => !v)}
                >
                  {taskExpanded() ? "less" : "more"}
                </button>
              </Show>
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
          <Show when={props.pod.ForwardedPorts && props.pod.ForwardedPorts.length > 0}>
            <div>
              <span class="text-text-weak">Ports: </span>
              <span class="text-text-secondary-base">
                {props.pod.ForwardedPorts!.map(
                  (p) => `${p.hostPort}→${p.containerPort}`
                ).join(", ")}
              </span>
            </div>
          </Show>
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
          <Show when={isRunning() && !isAdvisor()}>
            <div class="ml-auto">
              <Button
                variant={showSettings() ? "secondary" : "ghost"}
                size="small"
                onClick={() => setShowSettings((v) => !v)}
              >
                Settings
              </Button>
            </div>
          </Show>
        </div>

        {/* Action error */}
        <Show when={actionError()}>
          <Card variant="error" class="mx-4 mb-3 p-2">
            <span class="text-12-regular">{actionError()}</span>
          </Card>
        </Show>

        {/* Pod diagnostics (e.g. agent binary not found) */}
        <Show when={props.pod.Diagnostics}>
          {(diag) => (
            <div class="mx-4 mb-3 rounded border border-icon-warning-base/30 bg-icon-warning-base/10 p-3">
              <p class="text-12-regular text-text-primary">{diag().message}</p>
              <Show when={diag().suggestion}>
                <p class="text-11-regular text-text-subtle mt-1">{diag().suggestion}</p>
              </Show>
            </div>
          )}
        </Show>

        {/* Devaipod settings inline */}
        <Show when={showSettings()}>
          <DevaipodSettings podName={props.pod.Name} />
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
// Devaipod settings (inline in pod card)
// ---------------------------------------------------------------------------

function DevaipodSettings(props: { podName: string }) {
  const ctx = useDevaipod()
  const [titleValue, setTitleValue] = createSignal("")
  const [titleLoading, setTitleLoading] = createSignal(true)
  const [titleSaving, setTitleSaving] = createSignal(false)
  const [titleError, setTitleError] = createSignal("")
  const [titleEditing, setTitleEditing] = createSignal(false)

  // Load current title on mount
  onMount(async () => {
    try {
      const resp = await ctx.getTitle(props.podName)
      setTitleValue(resp?.title ?? "")
    } catch {
      // Fall back to label if pod-api unreachable
      const pod = ctx.pods.find((p) => p.Name === props.podName)
      setTitleValue(pod?.Labels?.["io.devaipod.title"] ?? "")
    } finally {
      setTitleLoading(false)
    }
  })

  async function saveTitle() {
    setTitleSaving(true)
    setTitleError("")
    try {
      const resp = await ctx.updateTitle(props.podName, titleValue())
      setTitleValue(resp?.title ?? titleValue())
      setTitleEditing(false)
    } catch (err) {
      setTitleError(err instanceof Error ? err.message : String(err))
    } finally {
      setTitleSaving(false)
    }
  }

  return (
    <div class="border-t border-border-base">
      {/* Title section */}
      <div class="px-4 pt-3 pb-3">
        <div class="flex items-center gap-2 mb-3">
          <Icon name="settings-gear" size="small" class="text-text-weak" />
          <span class="text-12-medium text-text-secondary-base">Session Settings</span>
        </div>

        <Show when={titleLoading()}>
          <div class="flex items-center gap-2 text-12-regular text-text-weak">
            <Spinner class="size-3.5" />
            Loading...
          </div>
        </Show>

        <Show when={!titleLoading()}>
          <div class="mb-1">
            <span class="text-12-medium text-text-strong">Title</span>
            <p class="text-11-regular text-text-weak">A short description of this session</p>
          </div>
          <Show when={titleEditing()} fallback={
            <div class="flex items-center gap-2">
              <span class="text-12-regular text-text-secondary-base flex-1 truncate">
                {titleValue() || "(no title)"}
              </span>
              <Button
                variant="ghost"
                size="small"
                onClick={() => setTitleEditing(true)}
              >
                Edit
              </Button>
            </div>
          }>
            <div class="flex items-center gap-2">
              <input
                type="text"
                class="flex-1 text-12-regular bg-background-base border border-border-base rounded px-2 py-1 text-text-strong focus:outline-none focus:border-border-active-base"
                value={titleValue()}
                onInput={(e) => setTitleValue(e.currentTarget.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") saveTitle()
                  if (e.key === "Escape") setTitleEditing(false)
                }}
                placeholder="e.g. refactoring auth middleware"
                autofocus
                disabled={titleSaving()}
              />
              <Button
                variant="primary"
                size="small"
                onClick={saveTitle}
                disabled={titleSaving()}
              >
                {titleSaving() ? "Saving..." : "Save"}
              </Button>
              <Button
                variant="ghost"
                size="small"
                onClick={() => setTitleEditing(false)}
                disabled={titleSaving()}
              >
                Cancel
              </Button>
            </div>
          </Show>
          <Show when={titleError()}>
            <Card variant="error" class="mt-2 p-2">
              <span class="text-11-regular">{titleError()}</span>
            </Card>
          </Show>
        </Show>
      </div>

      {/* Gator controls as a subsection */}
      <GatorControls podName={props.podName} />
    </div>
  )
}

// ---------------------------------------------------------------------------
// Gator controls (inline in pod card)
// ---------------------------------------------------------------------------

function GatorControls(props: { podName: string }) {
  const ctx = useDevaipod()
  const [loading, setLoading] = createSignal(true)
  const [gatorState, setGatorState] = createSignal<GatorScopesResponse | null>(null)
  const [saving, setSaving] = createSignal(false)
  const [error, setError] = createSignal("")

  // Fetch current gator scopes
  onMount(async () => {
    try {
      const resp = await ctx.getGatorScopes(props.podName)
      setGatorState(resp)
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setLoading(false)
    }
  })

  // Derive the "target repo" pattern — the first non-wildcard repo, or the wildcard
  const targetRepo = createMemo(() => {
    const scopes = gatorState()?.scopes
    if (!scopes?.gh?.repos) return null
    const repos = Object.keys(scopes.gh.repos)
    return repos.find((r) => !r.includes("*")) ?? repos[0] ?? null
  })

  // Current permission state for the target repo
  const repoPerms = createMemo(() => {
    const repo = targetRepo()
    if (!repo) return null
    return gatorState()?.scopes?.gh?.repos?.[repo] ?? null
  })

  const hasDraftPr = createMemo(() => {
    const p = repoPerms()
    return !!(p?.["create-draft"] || p?.["push-new-branch"])
  })

  const hasDraftReview = createMemo(() => {
    return !!repoPerms()?.["pending-review"]
  })

  async function togglePermission(
    permission: "draft-pr" | "draft-review",
    enabled: boolean,
  ) {
    const state = gatorState()
    if (!state?.scopes) return

    setSaving(true)
    setError("")

    try {
      // Deep clone current scopes
      const newScopes: GatorScopeConfig = JSON.parse(JSON.stringify(state.scopes))

      if (!newScopes.gh) newScopes.gh = {}
      if (!newScopes.gh.repos) newScopes.gh.repos = {}

      // Find the target repo to update
      const repo = targetRepo()
      if (!repo) return

      const perms = newScopes.gh.repos[repo] ?? { read: true }

      if (permission === "draft-pr") {
        perms["create-draft"] = enabled
        perms["push-new-branch"] = enabled
      } else {
        perms["pending-review"] = enabled
      }

      newScopes.gh.repos[repo] = perms

      const resp = await ctx.updateGatorScopes(props.podName, newScopes)
      setGatorState(resp)
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setSaving(false)
    }
  }

  return (
    <div class="px-4 pb-3 border-t border-border-base pt-3">
      <div class="flex items-center gap-2 mb-3">
        <Icon name="sliders" size="small" class="text-text-weak" />
        <span class="text-12-medium text-text-secondary-base">Service Gator</span>
      </div>

      <Show when={loading()}>
        <div class="flex items-center gap-2 text-12-regular text-text-weak">
          <Spinner class="size-3.5" />
          Loading permissions...
        </div>
      </Show>

      <Show when={!loading() && !gatorState()?.enabled}>
        <p class="text-12-regular text-text-weak">
          Service-gator is not enabled for this workspace.
        </p>
      </Show>

      <Show when={!loading() && gatorState()?.enabled}>
        <Show
          when={targetRepo()}
          fallback={
            <p class="text-12-regular text-text-weak">
              Read-only access enabled. No repository scopes configured for write control.
            </p>
          }
        >
          <p class="text-11-regular text-text-weak mb-3">
            <span class="font-mono">{targetRepo()}</span>
          </p>

          <div class="flex flex-col gap-3">
            <div class="flex items-center justify-between">
              <div>
                <span class="text-12-medium text-text-strong">Draft PRs</span>
                <p class="text-11-regular text-text-weak">Create draft pull requests and push branches</p>
              </div>
              <SwitchToggle
                checked={hasDraftPr()}
                disabled={saving()}
                onChange={(checked) => togglePermission("draft-pr", checked)}
              />
            </div>

            <div class="flex items-center justify-between">
              <div>
                <span class="text-12-medium text-text-strong">Draft Reviews</span>
                <p class="text-11-regular text-text-weak">Create pending PR reviews with comments</p>
              </div>
              <SwitchToggle
                checked={hasDraftReview()}
                disabled={saving()}
                onChange={(checked) => togglePermission("draft-review", checked)}
              />
            </div>
          </div>

          <Show when={saving()}>
            <div class="flex items-center gap-2 mt-2 text-11-regular text-text-weak">
              <Spinner class="size-3" />
              Updating...
            </div>
          </Show>
        </Show>
      </Show>

      <Show when={error()}>
        <Card variant="error" class="mt-2 p-2">
          <span class="text-11-regular">{error()}</span>
        </Card>
      </Show>
    </div>
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

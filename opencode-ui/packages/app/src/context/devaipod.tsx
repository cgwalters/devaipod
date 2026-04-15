import { createSimpleContext } from "@opencode-ai/ui/context"
import { batch, createEffect, createMemo, createSignal, onCleanup, untrack } from "solid-js"
import { createStore, produce, reconcile } from "solid-js/store"
import { apiFetch } from "@/utils/devaipod-api"

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Pod info from the unified /api/devaipod/pods endpoint (server-side naming). */
interface ForwardedPort {
  container_port: number
  host_port: number
}

interface RawUnifiedPod {
  name: string
  status: string
  created: string
  labels?: Record<string, string>
  containers?: Array<{ Names: string; Status: string }>
  agent_status?: AgentStatus
  last_active_ts?: number
  needs_update: boolean
  forwarded_ports?: ForwardedPort[]
  diagnostics?: { code: string; message: string; suggestion?: string }
}

export interface PodInfo {
  Name: string
  Status: string
  Created: string
  Labels?: Record<string, string>
  Containers?: Array<{ Names: string; Status: string }>
  ForwardedPorts?: Array<{ containerPort: number; hostPort: number }>
  /** Last time the agent was active (unix ms), from server cache. */
  LastActiveTs?: number
  /** Diagnostic info for degraded pods (e.g. agent binary not found). */
  Diagnostics?: { code: string; message: string; suggestion?: string }
}

export interface AgentStatus {
  activity: "Working" | "Idle" | "Stopped" | "Unknown"
  current_tool?: string
  status_line?: string
  session_count?: number
  completion_status?: "active" | "done"
  title?: string
  last_message_ts?: number
}

export interface LaunchState {
  state: "launching" | "failed"
  error?: string
}

export interface Proposal {
  id: string
  title: string
  repo: string
  rationale: string
  priority: "high" | "medium" | "low"
  status: string
  source?: string
}

export interface LaunchWorkspaceParams {
  source: string
  task?: string
  name?: string
  image?: string
  service_gator_scopes?: string[]
  service_gator_image?: string
  service_gator_ro?: boolean
  devcontainer_json?: string
  use_default_devcontainer?: boolean
  title?: string
}

/** A recently-used source from the server (local path or remote URL). */
export interface RecentSource {
  source: string
  last_used: string
}

/** Pod info from the devcontainer list endpoint. */
export interface DevcontainerPod {
  name: string
  status: string
  created: string
  labels?: Record<string, string>
  containers?: { Names: string; Status: string }[]
}

// ---------------------------------------------------------------------------
// Control-plane types (repo-grouped view)
// ---------------------------------------------------------------------------

export interface ControlPlaneAgent {
  name: string
  short_name: string
  status: string
  task?: string
  title?: string
  completion_status?: string
  last_active?: string
  is_running: boolean
  created: string
}

export interface ControlPlaneDevcontainer {
  name: string
  short_name: string
  status: string
  created: string
  is_running: boolean
}

export interface ControlPlaneRepo {
  repo: string
  active_count: number
  agents: ControlPlaneAgent[]
  devcontainers: ControlPlaneDevcontainer[]
}

/** GitHub repo permission flags from the gator config */
export interface GhRepoPermission {
  read?: boolean
  "create-draft"?: boolean
  "pending-review"?: boolean
  "push-new-branch"?: boolean
  write?: boolean
}

/** GitHub scope section of gator config */
export interface GhScope {
  read?: boolean
  repos?: Record<string, GhRepoPermission>
}

/** Full gator scope config (matches JwtScopeConfig on the backend) */
export interface GatorScopeConfig {
  gh?: GhScope
}

/** Response from GET /api/devaipod/pods/{name}/gator-scopes */
export interface GatorScopesResponse {
  enabled: boolean
  scopes?: GatorScopeConfig
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const PODMAN_PODS = "/api/podman/v5.0.0/libpod/pods"
const POD_POLL_MS = 5_000
const LAUNCH_POLL_MS = 3_000
const PROPOSAL_POLL_MS = 10_000


// ---------------------------------------------------------------------------
// Frecency sort & time sections
// ---------------------------------------------------------------------------

export type TimeSection = "Active Today" | "This Week" | "This Month" | "Older"

export type SortBy = "activity" | "repo" | "created"
export type GroupBy = "time" | "repo" | "status" | "none"
export type Density = "comfortable" | "compact"

export interface PodGroup {
  label: string
  pods: PodInfo[]
}

const ADVISOR_POD_NAME = "devaipod-advisor"
const MS_DAY = 86_400_000
const MS_WEEK = 7 * MS_DAY
const MS_MONTH = 30 * MS_DAY

/** Classify a timestamp into a time section relative to now. */
export function timeSection(ts: number, now: number): TimeSection {
  const d = new Date(now)
  const startOfToday = new Date(d.getFullYear(), d.getMonth(), d.getDate()).getTime()
  if (ts >= startOfToday) return "Active Today"
  const age = now - ts
  if (age < MS_WEEK) return "This Week"
  if (age < MS_MONTH) return "This Month"
  return "Older"
}

/** Get the effective timestamp for sorting: last_active_ts if available, else Created. */
export function effectiveTimestamp(pod: PodInfo): number {
  if (pod.LastActiveTs !== undefined) return pod.LastActiveTs
  const t = new Date(pod.Created).getTime()
  return Number.isNaN(t) ? 0 : t
}

/**
 * Sort pods by frecency: advisor first, then running before stopped,
 * then by last-active (or created) descending within each group.
 */
export function frecencySortPods(pods: PodInfo[]): PodInfo[] {
  return [...pods].sort((a, b) => {
    // Advisor always first (name ends with -advisor for multi-instance support)
    const aAdvisor = a.Name.endsWith("-advisor") ? 1 : 0
    const bAdvisor = b.Name.endsWith("-advisor") ? 1 : 0
    if (aAdvisor !== bAdvisor) return bAdvisor - aAdvisor

    // Running before stopped
    const aRunning = (a.Status ?? "").toLowerCase() === "running" ? 1 : 0
    const bRunning = (b.Status ?? "").toLowerCase() === "running" ? 1 : 0
    if (aRunning !== bRunning) return bRunning - aRunning

    // Within same status group: sort by effective timestamp descending
    return effectiveTimestamp(b) - effectiveTimestamp(a)
  })
}

/**
 * Sort pods alphabetically by repo label, then by effective timestamp descending
 * within each repo. Running pods sort above stopped within the same repo.
 * Advisor pod always first.
 */
export function sortByRepo(pods: PodInfo[]): PodInfo[] {
  return [...pods].sort((a, b) => {
    const aAdvisor = a.Name === ADVISOR_POD_NAME ? 1 : 0
    const bAdvisor = b.Name === ADVISOR_POD_NAME ? 1 : 0
    if (aAdvisor !== bAdvisor) return bAdvisor - aAdvisor

    const aRepo = (a.Labels?.["io.devaipod.repo"] ?? "").toLowerCase()
    const bRepo = (b.Labels?.["io.devaipod.repo"] ?? "").toLowerCase()
    if (aRepo !== bRepo) return aRepo.localeCompare(bRepo)

    const aRunning = (a.Status ?? "").toLowerCase() === "running" ? 1 : 0
    const bRunning = (b.Status ?? "").toLowerCase() === "running" ? 1 : 0
    if (aRunning !== bRunning) return bRunning - aRunning

    return effectiveTimestamp(b) - effectiveTimestamp(a)
  })
}

/**
 * Sort pods by Created timestamp descending. Advisor pod always first.
 */
export function sortByCreated(pods: PodInfo[]): PodInfo[] {
  return [...pods].sort((a, b) => {
    const aAdvisor = a.Name === ADVISOR_POD_NAME ? 1 : 0
    const bAdvisor = b.Name === ADVISOR_POD_NAME ? 1 : 0
    if (aAdvisor !== bAdvisor) return bAdvisor - aAdvisor

    // Use Created directly (ignoring LastActiveTs), falling back to 0 for invalid dates
    const aTime = new Date(a.Created).getTime()
    const bTime = new Date(b.Created).getTime()
    return (Number.isNaN(bTime) ? 0 : bTime) - (Number.isNaN(aTime) ? 0 : aTime)
  })
}

/** Dispatch to the correct sort function based on SortBy value. */
export function sortPods(pods: PodInfo[], by: SortBy): PodInfo[] {
  switch (by) {
    case "activity": return frecencySortPods(pods)
    case "repo": return sortByRepo(pods)
    case "created": return sortByCreated(pods)
  }
}

/**
 * Group pods into labeled sections.
 *
 * @param pods - already sorted and filtered (group order preserves input sort order)
 * @param by - grouping mode
 * @param agentStatusLookup - function to get AgentStatus for a pod name
 */
export function groupPods(
  pods: PodInfo[],
  by: GroupBy,
  agentStatusLookup: (name: string) => AgentStatus | undefined,
): PodGroup[] {
  if (by === "none") {
    return pods.length > 0 ? [{ label: "", pods }] : []
  }

  if (by === "time") {
    const now = Date.now()
    const buckets = new Map<string, PodInfo[]>()
    const order: TimeSection[] = ["Active Today", "This Week", "This Month", "Older"]
    for (const pod of pods) {
      const sec = timeSection(effectiveTimestamp(pod), now)
      let list = buckets.get(sec)
      if (!list) {
        list = []
        buckets.set(sec, list)
      }
      list.push(pod)
    }
    const groups: PodGroup[] = []
    for (const sec of order) {
      const list = buckets.get(sec)
      if (list && list.length > 0) {
        groups.push({ label: sec, pods: list })
      }
    }
    return groups
  }

  if (by === "repo") {
    const buckets = new Map<string, PodInfo[]>()
    const order: string[] = []
    for (const pod of pods) {
      const repo = pod.Labels?.["io.devaipod.repo"] ?? ""
      const key = repo || "Other"
      let list = buckets.get(key)
      if (!list) {
        list = []
        buckets.set(key, list)
        order.push(key)
      }
      list.push(pod)
    }
    return order.map((key) => ({ label: key, pods: buckets.get(key)! }))
  }

  // by === "status"
  // "Working" = autonomously active, no attention needed
  // "Needs Attention" = running but idle/unknown, may need user input
  // "Inactive" = stopped or marked done (even if still running)
  const working: PodInfo[] = []
  const needsAttention: PodInfo[] = []
  const inactive: PodInfo[] = []

  for (const pod of pods) {
    const isRunning = (pod.Status ?? "").toLowerCase() === "running"
    const status = agentStatusLookup(pod.Name)
    const isDone = status?.completion_status === "done"

    if (!isRunning || isDone) {
      inactive.push(pod)
    } else if (status?.activity === "Working") {
      working.push(pod)
    } else {
      needsAttention.push(pod)
    }
  }

  const groups: PodGroup[] = []
  if (working.length > 0) groups.push({ label: "Working", pods: working })
  if (needsAttention.length > 0) groups.push({ label: "Needs Attention", pods: needsAttention })
  if (inactive.length > 0) groups.push({ label: "Inactive", pods: inactive })
  return groups
}

// ---------------------------------------------------------------------------
// Context
// ---------------------------------------------------------------------------

export const { use: useDevaipod, provider: DevaipodProvider } = createSimpleContext({
  name: "Devaipod",
  gate: false,
  init: () => {
    // -- Reactive state -----------------------------------------------------

    const [store, setStore] = createStore({
      pods: [] as PodInfo[],
      launches: {} as Record<string, LaunchState>,
      agentStatus: {} as Record<string, AgentStatus>,
      enrichment: {} as Record<string, { needs_update: boolean }>,
      proposals: [] as Proposal[],
      recentSources: [] as RecentSource[],
      devcontainers: [] as DevcontainerPod[],
      controlPlane: [] as ControlPlaneRepo[],
      connected: undefined as boolean | undefined,
      error: undefined as string | undefined,
    })

    const [refreshCounter, setRefreshCounter] = createSignal(0)

    // -- Pod list (unified: pods + agent status + enrichment) ----------------

    async function fetchPods() {
      try {
        const raw = await apiFetch<RawUnifiedPod[]>("/api/devaipod/pods")
        // Map server-side field names to the PodInfo shape used by the UI
        const pods: PodInfo[] = raw.map((p) => ({
          Name: p.name,
          Status: p.status,
          Created: p.created,
          Labels: p.labels,
          Containers: p.containers,
          ForwardedPorts: p.forwarded_ports?.map((fp) => ({
            containerPort: fp.container_port,
            hostPort: fp.host_port,
          })),
          LastActiveTs: p.last_active_ts,
          Diagnostics: p.diagnostics,
        }))
        // Extract agent status and enrichment from the same response
        const agentMap: Record<string, AgentStatus> = {}
        const enrichMap: Record<string, { needs_update: boolean }> = {}
        for (const p of raw) {
          if (p.agent_status) {
            agentMap[p.name] = p.agent_status
          }
          enrichMap[p.name] = { needs_update: p.needs_update }
        }
        batch(() => {
          // Server already sorts (advisor first, running, then by date)
          setStore("pods", reconcile(pods, { key: "Name", merge: true }))
          setStore("agentStatus", reconcile(agentMap, { merge: true }))
          setStore("enrichment", reconcile(enrichMap, { merge: true }))
          setStore("connected", true)
          setStore("error", undefined)
        })
      } catch (err) {
        batch(() => {
          setStore("connected", false)
          setStore("error", err instanceof Error ? err.message : String(err))
        })
      }
    }

    // -- Launch state -------------------------------------------------------

    async function fetchLaunches() {
      try {
        const launches = await apiFetch<Record<string, LaunchState>>("/api/devaipod/launches")
        const oldLaunches = store.launches
        setStore("launches", reconcile(launches, { merge: true }))

        // Detect transitions that warrant a pod list refresh
        let needRefresh = false
        for (const podName of Object.keys(oldLaunches)) {
          if (oldLaunches[podName].state === "launching" && !launches[podName]) {
            needRefresh = true
          }
        }
        for (const [, info] of Object.entries(launches)) {
          if (info.state === "failed") {
            needRefresh = true
          }
        }
        if (needRefresh) {
          await fetchPods()
        }
      } catch {
        // Backend unavailable, ignore
      }
    }

    // -- Proposals ----------------------------------------------------------

    async function fetchProposals() {
      try {
        const proposals = await apiFetch<Proposal[]>("/api/devaipod/proposals")
        setStore("proposals", reconcile(proposals.filter((p) => p.status === "pending"), { key: "id", merge: true }))
      } catch {
        // Ignore
      }
    }

    // -- Recent sources (fetched once, refreshed on launch) ------------------

    async function fetchRecentSources() {
      try {
        const sources = await apiFetch<RecentSource[]>("/api/devaipod/recent-sources")
        setStore("recentSources", reconcile(sources, { key: "source", merge: true }))
      } catch {
        // Ignore — not critical
      }
    }

    // -- Devcontainer list ---------------------------------------------------

    async function fetchDevcontainers() {
      try {
        const list = await apiFetch<DevcontainerPod[]>("/api/devaipod/devcontainer/list")
        setStore("devcontainers", reconcile(list, { key: "name", merge: true }))
      } catch {
        // Ignore — endpoint may not exist on older backends
      }
    }

    // -- Control plane (repo-grouped view) -----------------------------------

    async function fetchControlPlane() {
      try {
        const data = await apiFetch<{ repos: ControlPlaneRepo[] }>("/api/devaipod/control-plane")
        setStore("controlPlane", reconcile(data.repos, { key: "repo", merge: true }))
      } catch {
        // Ignore — endpoint may not exist on older backends
      }
    }

    // -- Polling setup ------------------------------------------------------
    // Use self-scheduling setTimeout loops instead of setInterval so the next
    // poll is only queued after the current one finishes.  This makes request
    // pileup structurally impossible when the server is slow.

    let disposed = false
    onCleanup(() => { disposed = true })

    let podTimer: ReturnType<typeof setTimeout> | undefined
    function schedulePodPoll() {
      if (disposed) return
      podTimer = setTimeout(async () => {
        await fetchPods()
        schedulePodPoll()
      }, POD_POLL_MS)
    }
    schedulePodPoll()
    onCleanup(() => clearTimeout(podTimer))

    let launchTimer: ReturnType<typeof setTimeout> | undefined
    function scheduleLaunchPoll() {
      if (disposed) return
      launchTimer = setTimeout(async () => {
        if (Object.keys(store.launches).length > 0) {
          await fetchLaunches()
        }
        scheduleLaunchPoll()
      }, LAUNCH_POLL_MS)
    }
    scheduleLaunchPoll()
    onCleanup(() => clearTimeout(launchTimer))

    let proposalTimer: ReturnType<typeof setTimeout> | undefined
    function scheduleProposalPoll() {
      if (disposed) return
      proposalTimer = setTimeout(async () => {
        await fetchProposals()
        scheduleProposalPoll()
      }, PROPOSAL_POLL_MS)
    }
    scheduleProposalPoll()
    onCleanup(() => clearTimeout(proposalTimer))

    let devcontainerTimer: ReturnType<typeof setTimeout> | undefined
    function scheduleDevcontainerPoll() {
      if (disposed) return
      devcontainerTimer = setTimeout(async () => {
        await fetchDevcontainers()
        scheduleDevcontainerPoll()
      }, POD_POLL_MS)
    }
    scheduleDevcontainerPoll()
    onCleanup(() => clearTimeout(devcontainerTimer))

    let controlPlaneTimer: ReturnType<typeof setTimeout> | undefined
    function scheduleControlPlanePoll() {
      if (disposed) return
      controlPlaneTimer = setTimeout(async () => {
        await fetchControlPlane()
        scheduleControlPlanePoll()
      }, POD_POLL_MS)
    }
    scheduleControlPlanePoll()
    onCleanup(() => clearTimeout(controlPlaneTimer))

    // Initial fetch — the effect tracks only refreshCounter; the async bodies
    // read store state (e.g. store.pods, store.launches) which must NOT be tracked
    // here or we'd create a feedback loop (fetch updates store → effect re-fires).
    createEffect(() => {
      refreshCounter()
      untrack(() => {
        fetchPods()
        fetchLaunches()
        fetchProposals()
        fetchRecentSources()
        fetchDevcontainers()
        fetchControlPlane()
      })
    })

    // -- Actions ------------------------------------------------------------

    function refresh() {
      setRefreshCounter((c) => c + 1)
    }

    async function openPod(fullName: string) {
      window.location.href = `/agent/${encodeURIComponent(fullName)}`
    }

    async function startPod(fullName: string) {
      await apiFetch<void>(`${PODMAN_PODS}/${encodeURIComponent(fullName)}/start`, {
        method: "POST",
      })
      refresh()
    }

    async function stopPod(fullName: string) {
      await apiFetch<void>(`${PODMAN_PODS}/${encodeURIComponent(fullName)}/stop`, {
        method: "POST",
      })
      refresh()
    }

    async function deletePod(fullName: string) {
      await apiFetch<void>(`${PODMAN_PODS}/${encodeURIComponent(fullName)}?force=true`, {
        method: "DELETE",
      })
      refresh()
    }

    async function recreatePod(fullName: string) {
      await apiFetch<void>(`/api/devaipod/pods/${encodeURIComponent(fullName)}/recreate`, {
        method: "POST",
      })
      refresh()
    }

    async function launchWorkspace(params: LaunchWorkspaceParams) {
      const result = await apiFetch<{ success: boolean; message?: string; pod_name?: string }>(
        "/api/devaipod/run",
        {
          method: "POST",
          body: JSON.stringify(params),
        },
      )
      if (!result.success) {
        throw new Error(result.message ?? "Launch failed")
      }
      if (result.pod_name) {
        setStore("launches", result.pod_name, { state: "launching" })
      }
      refresh()
      // Refresh recent sources so the launcher picks up the new entry
      fetchRecentSources()
      return result
    }

    async function launchAdvisor() {
      const result = await apiFetch<{ success: boolean; message?: string }>(
        "/api/devaipod/advisor/launch",
        {
          method: "POST",
          body: JSON.stringify({}),
        },
      )
      if (!result.success) {
        throw new Error(result.message ?? "Launch failed")
      }
      refresh()
    }

    async function dismissLaunch(podName: string) {
      try {
        await apiFetch<void>(`/api/devaipod/launches/${encodeURIComponent(podName)}`, {
          method: "DELETE",
        })
      } catch {
        // ignore
      }
      setStore(
        produce((s) => {
          delete s.launches[podName]
        }),
      )
      refresh()
    }

    async function dismissProposal(id: string) {
      try {
        await apiFetch<void>(`/api/devaipod/proposals/${encodeURIComponent(id)}/dismiss`, {
          method: "POST",
        })
      } catch {
        // ignore
      }
      fetchProposals()
    }

    async function launchDevcontainer(source: string, opts?: { name?: string; image?: string }) {
      const body: Record<string, string> = { source }
      if (opts?.name) body.name = opts.name
      if (opts?.image) body.image = opts.image
      const result = await apiFetch<{ success: boolean; message?: string }>(
        "/api/devaipod/devcontainer/run",
        { method: "POST", body: JSON.stringify(body) },
      )
      if (!result.success) {
        throw new Error(result.message ?? "Devcontainer launch failed")
      }
      fetchDevcontainers()
      return result
    }

    async function deleteDevcontainer(name: string) {
      await apiFetch<void>(`/api/devaipod/devcontainer/${encodeURIComponent(name)}`, {
        method: "DELETE",
      })
      fetchDevcontainers()
    }

    async function stopDevcontainer(name: string) {
      await apiFetch<void>(`${PODMAN_PODS}/${encodeURIComponent(name)}/stop`, {
        method: "POST",
      })
      fetchDevcontainers()
    }

    async function startDevcontainer(name: string) {
      await apiFetch<void>(`${PODMAN_PODS}/${encodeURIComponent(name)}/start`, {
        method: "POST",
      })
      fetchDevcontainers()
    }

    async function getTitle(fullName: string): Promise<{ title: string | null }> {
      return apiFetch<{ title: string | null }>(
        `/api/devaipod/pods/${encodeURIComponent(fullName)}/pod-api/title`,
      )
    }

    async function updateTitle(
      fullName: string,
      title: string,
    ): Promise<{ title: string | null }> {
      const result = await apiFetch<{ title: string | null }>(
        `/api/devaipod/pods/${encodeURIComponent(fullName)}/pod-api/title`,
        {
          method: "PUT",
          body: JSON.stringify({ title }),
        },
      )
      // Trigger a pod list refresh so the title shows up immediately
      setRefreshCounter((c) => c + 1)
      return result
    }

    async function getGatorScopes(fullName: string): Promise<GatorScopesResponse> {
      return apiFetch<GatorScopesResponse>(
        `/api/devaipod/pods/${encodeURIComponent(fullName)}/gator-scopes`,
      )
    }

    async function updateGatorScopes(
      fullName: string,
      scopes: GatorScopeConfig,
    ): Promise<GatorScopesResponse> {
      return apiFetch<GatorScopesResponse>(
        `/api/devaipod/pods/${encodeURIComponent(fullName)}/gator-scopes`,
        {
          method: "PUT",
          body: JSON.stringify({ scopes }),
        },
      )
    }

    // -- Derived state ------------------------------------------------------

    const hasAdvisor = createMemo(() => store.pods.some((p) => p.Name.endsWith("-advisor")))

    const hasActiveLaunches = createMemo(
      () => Object.values(store.launches).some((l) => l.state === "launching"),
    )

    // -- Public API ---------------------------------------------------------

    return {
      get pods() {
        return store.pods
      },
      get launches() {
        return store.launches
      },
      get agentStatus() {
        return store.agentStatus
      },
      get enrichment() {
        return store.enrichment
      },
      get proposals() {
        return store.proposals
      },
      get recentSources() {
        return store.recentSources
      },
      get devcontainers() {
        return store.devcontainers
      },
      get controlPlane() {
        return store.controlPlane
      },
      get connected() {
        return store.connected
      },
      get error() {
        return store.error
      },
      hasAdvisor,
      hasActiveLaunches,
      refresh,
      openPod,
      startPod,
      stopPod,
      deletePod,
      recreatePod,
      launchWorkspace,
      launchAdvisor,
      dismissLaunch,
      dismissProposal,
      launchDevcontainer,
      deleteDevcontainer,
      stopDevcontainer,
      startDevcontainer,
      getTitle,
      updateTitle,
      getGatorScopes,
      updateGatorScopes,
    }
  },
})

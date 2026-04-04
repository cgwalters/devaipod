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
  no_auto_approve?: boolean
}

/** A recently-used source from the server (local path or remote URL). */
export interface RecentSource {
  source: string
  last_used: string
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
    // Advisor always first
    const aAdvisor = a.Name === "devaipod-advisor" ? 1 : 0
    const bAdvisor = b.Name === "devaipod-advisor" ? 1 : 0
    if (aAdvisor !== bAdvisor) return bAdvisor - aAdvisor

    // Running before stopped
    const aRunning = (a.Status ?? "").toLowerCase() === "running" ? 1 : 0
    const bRunning = (b.Status ?? "").toLowerCase() === "running" ? 1 : 0
    if (aRunning !== bRunning) return bRunning - aRunning

    // Within same status group: sort by effective timestamp descending
    return effectiveTimestamp(b) - effectiveTimestamp(a)
  })
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

    const hasAdvisor = createMemo(() => store.pods.some((p) => p.Name === "devaipod-advisor"))

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
      getTitle,
      updateTitle,
      getGatorScopes,
      updateGatorScopes,
    }
  },
})

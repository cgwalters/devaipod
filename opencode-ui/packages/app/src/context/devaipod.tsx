import { createSimpleContext } from "@opencode-ai/ui/context"
import { batch, createEffect, createMemo, createSignal, onCleanup, untrack } from "solid-js"
import { createStore, produce, reconcile } from "solid-js/store"
import { apiFetch, getAuthToken } from "@/utils/devaipod-api"

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface PodInfo {
  Name: string
  Status: string
  Created: string
  Labels?: Record<string, string>
  Containers?: Array<{ Names: string; Status: string }>
}

export interface AgentStatus {
  activity: "Working" | "Idle" | "Stopped" | "Unknown"
  current_tool?: string
  status_line?: string
  session_count?: number
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
const AGENT_POLL_MS = 3_000
const PROPOSAL_POLL_MS = 10_000
const ENRICHMENT_POLL_MS = 15_000

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
      connected: undefined as boolean | undefined,
      error: undefined as string | undefined,
    })

    const [refreshCounter, setRefreshCounter] = createSignal(0)

    // -- Pod list -----------------------------------------------------------

    function sortPods(pods: PodInfo[]): PodInfo[] {
      return pods.slice().sort((a, b) => {
        // Pin advisor to top
        const aAdvisor = a.Name === "devaipod-advisor" ? 1 : 0
        const bAdvisor = b.Name === "devaipod-advisor" ? 1 : 0
        if (bAdvisor !== aAdvisor) return bAdvisor - aAdvisor
        // Running pods first
        const aRunning = (a.Status ?? "").toLowerCase() === "running" ? 1 : 0
        const bRunning = (b.Status ?? "").toLowerCase() === "running" ? 1 : 0
        if (bRunning !== aRunning) return bRunning - aRunning
        // Newest first
        return (b.Created ?? "").localeCompare(a.Created ?? "")
      })
    }

    async function fetchPods() {
      try {
        const all = await apiFetch<PodInfo[]>(`${PODMAN_PODS}/json`)
        const devaipodPods = sortPods(all.filter((p) => p.Name?.startsWith("devaipod-")))
        batch(() => {
          setStore("pods", reconcile(devaipodPods, { key: "Name", merge: false }))
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
        setStore("launches", reconcile(launches))

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

    // -- Agent status -------------------------------------------------------

    async function fetchAgentStatus() {
      const running = store.pods.filter((p) => (p.Status ?? "").toLowerCase() === "running")
      const results = await Promise.allSettled(
        running.map(async (pod) => {
          const status = await apiFetch<AgentStatus>(
            `/api/devaipod/pods/${encodeURIComponent(pod.Name)}/agent-status`,
          )
          return { name: pod.Name, status }
        }),
      )
      setStore(
        produce((s) => {
          for (const r of results) {
            if (r.status === "fulfilled") {
              s.agentStatus[r.value.name] = r.value.status
            }
          }
        }),
      )
    }

    // -- Pod enrichment (update detection) -----------------------------------

    async function fetchEnrichment() {
      try {
        const data = await apiFetch<Record<string, { needs_update: boolean }>>(
          "/api/devaipod/pods/enrichment",
        )
        setStore("enrichment", reconcile(data))
      } catch {
        // Ignore — enrichment is best-effort
      }
    }

    // -- Proposals ----------------------------------------------------------

    async function fetchProposals() {
      try {
        const proposals = await apiFetch<Proposal[]>("/api/devaipod/proposals")
        setStore("proposals", reconcile(proposals.filter((p) => p.status === "pending"), { key: "id", merge: false }))
      } catch {
        // Ignore
      }
    }

    // -- Polling setup ------------------------------------------------------

    const podInterval = setInterval(() => {
      fetchPods()
    }, POD_POLL_MS)
    onCleanup(() => clearInterval(podInterval))

    const launchInterval = setInterval(() => {
      if (Object.keys(store.launches).length > 0) {
        fetchLaunches()
      }
    }, LAUNCH_POLL_MS)
    onCleanup(() => clearInterval(launchInterval))

    const agentInterval = setInterval(() => {
      fetchAgentStatus()
    }, AGENT_POLL_MS)
    onCleanup(() => clearInterval(agentInterval))

    const enrichmentInterval = setInterval(() => {
      fetchEnrichment()
    }, ENRICHMENT_POLL_MS)
    onCleanup(() => clearInterval(enrichmentInterval))

    const proposalInterval = setInterval(() => {
      fetchProposals()
    }, PROPOSAL_POLL_MS)
    onCleanup(() => clearInterval(proposalInterval))

    // Initial fetch — the effect tracks only refreshCounter; the async bodies
    // read store state (e.g. store.pods, store.launches) which must NOT be tracked
    // here or we'd create a feedback loop (fetch updates store → effect re-fires).
    createEffect(() => {
      refreshCounter()
      untrack(() => {
        fetchPods()
        fetchLaunches()
        fetchAgentStatus()
        fetchEnrichment()
        fetchProposals()
      })
    })

    // -- Actions ------------------------------------------------------------

    function refresh() {
      setRefreshCounter((c) => c + 1)
    }

    async function openPod(fullName: string) {
      const info = await apiFetch<{
        latest_session?: { id: string; directory: string }
      }>(`/api/devaipod/pods/${encodeURIComponent(fullName)}/opencode-info`)

      let qs = ""
      if (info.latest_session) {
        const dir = btoa(info.latest_session.directory)
        qs = `?dir=${encodeURIComponent(dir)}&session=${encodeURIComponent(info.latest_session.id)}`
      }
      window.location.href = `/_devaipod/agent/${encodeURIComponent(fullName)}/${qs}`
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
      getGatorScopes,
      updateGatorScopes,
    }
  },
})

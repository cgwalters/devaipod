import { createEffect, createResource, on, onCleanup, onMount, Show, type JSX } from "solid-js"
import { createStore } from "solid-js/store"
import type { FileDiff } from "@opencode-ai/sdk/v2"
import { SessionReview } from "@opencode-ai/ui/session-review"
import { Select } from "@opencode-ai/ui/select"
import type { SelectedLineRange } from "@/context/file"
import type { LineComment } from "@/context/comments"
import { apiFetch } from "@/utils/devaipod-api"

export type DiffStyle = "unified" | "split"

export interface GitReviewTabProps {
  diffStyle: DiffStyle
  onDiffStyleChange?: (style: DiffStyle) => void
  onLineComment?: (comment: { file: string; selection: SelectedLineRange; comment: string; preview?: string }) => void
  comments?: LineComment[]
  focusedComment?: { file: string; id: string } | null
  onFocusedCommentChange?: (focus: { file: string; id: string } | null) => void
  focusedFile?: string
  onScrollRef?: (el: HTMLDivElement) => void
  classes?: {
    root?: string
    header?: string
    container?: string
  }
}

interface GitLogEntry {
  sha: string
  short_sha: string
  message: string
  author: string
  author_email: string
  timestamp: string
  parents: string[]
}

interface ApiFileDiff {
  file: string
  before: string
  after: string
  additions: number
  deletions: number
  status: "added" | "deleted" | "modified"
}

function commitLabel(entry: GitLogEntry): string {
  const firstLine = entry.message.split("\n", 1)[0] ?? ""
  const subject = firstLine.length > 60 ? firstLine.slice(0, 57) + "..." : firstLine
  return `${entry.short_sha} ${subject}`
}

export function GitReviewTab(props: GitReviewTabProps) {
  const [state, setState] = createStore({
    baseCommit: undefined as string | undefined,
    gitUnavailable: false,
    fetchInFlight: false,
    fetchStatus: undefined as string | undefined,
    branch: undefined as string | undefined,
  })

  // Fetch current branch name from /git/status
  const [_status, { refetch: refetchStatus }] = createResource(
    () => true,
    async () => {
      try {
        const data = await apiFetch<{ branch?: string }>("/git/status")
        setState("branch", data.branch ?? undefined)
        return data
      } catch {
        return undefined
      }
    },
  )

  // The SPA runs on the pod-api sidecar which serves git endpoints at /git/*.
  const [log, { refetch: refetchLog }] = createResource(
    () => true,
    async () => {
      try {
        const data = await apiFetch<{ commits: GitLogEntry[] }>("/git/log")
        return data.commits
      } catch (err) {
        console.warn("Git log unavailable:", err)
        setState("gitUnavailable", true)
        return []
      }
    },
  )

  // Default to the earliest commit when log loads
  createEffect(
    on(
      () => log(),
      (entries) => {
        if (!entries || entries.length === 0) return
        if (state.baseCommit !== undefined) return
        // The log is typically newest-first; pick the last entry as default base
        setState("baseCommit", entries[entries.length - 1]!.sha)
      },
    ),
  )

  // Subscribe to git SSE events and auto-refresh when new commits arrive.
  // If the connection fails (e.g. workspace is not a git repo), just disable
  // auto-refresh silently instead of crashing.
  {
    onMount(() => {
      let es: EventSource | undefined
      try {
        es = new EventSource("/git/events")
      } catch (err) {
        console.warn("Git events SSE: failed to connect, auto-refresh disabled:", err)
        return
      }
      es.addEventListener("git.updated", (event) => {
        try {
          const payload = JSON.parse(event.data) as { head?: string }
          const currentHead = log()?.[0]?.sha
          if (payload.head && payload.head !== currentHead) {
            refetchLog()
            refetchStatus()
          }
        } catch (err) {
          console.warn("Failed to parse git.updated event:", err)
        }
      })
      es.onerror = () => {
        console.warn("Git events SSE error, closing connection. Auto-refresh disabled.")
        es!.close()
      }
      onCleanup(() => es!.close())
    })
  }

  async function handleFetchAgent() {
    if (state.fetchInFlight) return
    setState("fetchInFlight", true)
    setState("fetchStatus", undefined)
    try {
      const data = await apiFetch<{ success: boolean; message: string }>("/git/fetch-agent", {
        method: "POST",
      })
      setState("fetchStatus", data.success ? "Fetched" : `Error: ${data.message}`)
      if (data.success) {
        refetchLog()
        refetchStatus()
      }
    } catch (err) {
      setState("fetchStatus", `Error: ${err instanceof Error ? err.message : String(err)}`)
    } finally {
      setState("fetchInFlight", false)
      // Clear status message after a few seconds
      setTimeout(() => setState("fetchStatus", undefined), 4000)
    }
  }

  const diffParams = () => {
    const entries = log()
    if (!entries || entries.length === 0) return undefined
    const base = state.baseCommit
    if (!base) return undefined
    const head = entries[0]!.sha
    if (base === head) return undefined
    return { base, head }
  }

  const [diffData] = createResource(diffParams, async (params) => {
    try {
      const data = await apiFetch<{ files: ApiFileDiff[] }>(
        `/git/diff-range?base=${encodeURIComponent(params.base)}&head=${encodeURIComponent(params.head)}`,
      )
      return data.files
    } catch (err) {
      console.warn("Git diff-range unavailable:", err)
      setState("gitUnavailable", true)
      return []
    }
  })

  const diffs = (): FileDiff[] => {
    const files = diffData()
    if (!files) return []
    return files.map((f) => ({
      file: f.file,
      before: f.before,
      after: f.after,
      additions: f.additions,
      deletions: f.deletions,
      status: f.status,
    }))
  }

  const commitOptions = () => {
    const entries = log()
    if (!entries) return []
    return entries
  }

  const title = (): JSX.Element => (
    <div class="flex items-center gap-3">
      <span>Changes</span>
      <Show when={state.branch}>
        <span class="text-text-weak text-13-regular" data-action="branch-name">
          ({state.branch})
        </span>
      </Show>
      <Show when={commitOptions().length > 1}>
        <span class="text-text-weak text-13-regular">from</span>
        <Select
          options={commitOptions()}
          current={commitOptions().find((e) => e.sha === state.baseCommit)}
          value={(e) => e.sha}
          label={(e) => commitLabel(e)}
          onSelect={(entry) => entry && setState("baseCommit", entry.sha)}
          variant="ghost"
          size="small"
        />
      </Show>
      <button
        data-action="fetch-agent"
        class="text-13-regular px-2 py-0.5 rounded border border-border hover:bg-fill-element-hover disabled:opacity-50"
        disabled={state.fetchInFlight}
        onClick={handleFetchAgent}
      >
        {state.fetchInFlight ? "Fetching..." : "Fetch"}
      </button>
      <Show when={state.fetchStatus}>
        <span class="text-text-weak text-13-regular">{state.fetchStatus}</span>
      </Show>
    </div>
  )

  const loading = () => log.loading || diffData.loading

  return (
    <div data-component="git-review-tab">
      <Show
        when={!state.gitUnavailable}
        fallback={
          <div class="flex h-full items-center justify-center text-text-weak text-14-regular">
            Git review is not available for this workspace.
          </div>
        }
      >
        <Show
          when={!loading() || diffs().length > 0}
          fallback={
            <div class="flex h-full items-center justify-center text-text-weak text-14-regular">Loading...</div>
          }
        >
          <SessionReview
            title={title()}
            scrollRef={(el) => props.onScrollRef?.(el)}
            classes={{
              root: props.classes?.root ?? "pb-6",
              header: props.classes?.header ?? "px-6",
              container: props.classes?.container ?? "px-6",
            }}
            diffs={diffs()}
            diffStyle={props.diffStyle}
            onDiffStyleChange={props.onDiffStyleChange}
            focusedFile={props.focusedFile}
            onLineComment={props.onLineComment}
            comments={props.comments}
            focusedComment={props.focusedComment}
            onFocusedCommentChange={props.onFocusedCommentChange}
          />
        </Show>
      </Show>
    </div>
  )
}

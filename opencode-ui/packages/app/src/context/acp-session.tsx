/**
 * ACP session context for the devaipod agent page.
 *
 * Manages a WebSocket connection to pod-api's /ws/events endpoint,
 * parses incoming ACP events, and provides reactive signals for
 * messages, tool calls, permission requests, and connection state.
 */
import {
  createContext,
  createSignal,
  useContext,
  onCleanup,
  type ParentProps,
  batch,
  createEffect,
} from "solid-js"
import { createStore, produce } from "solid-js/store"
import { getAuthToken } from "@/utils/devaipod-api"
import type {
  AcpMessage,
  ToolCall,
  PermissionRequest,
  WsEnvelope,
  WsCommand,
  ContentBlock,
  ToolCallStatus,
  ToolCallContent,
  ToolCallDiff,
  ToolCallTerminal,
  SlashCommand,
  SessionModeState,
  SessionConfigOption,
  AgentInfo,
  AgentCapabilities,
  PlanEntry,
} from "@/types/acp"

// ---------------------------------------------------------------------------
// Store shape
// ---------------------------------------------------------------------------

export type ConnectionState = "connecting" | "connected" | "disconnected" | "error"

/** A timeline entry: either a message or a tool call, in arrival order. */
export type TimelineEntry =
  | { kind: "message"; id: string }
  | { kind: "toolCall"; id: string }

/** Per-session state (messages, tool calls, etc.) */
export interface SessionData {
  messages: AcpMessage[]
  toolCalls: Record<string, ToolCall>
  pendingPermissions: PermissionRequest[]
  prompting: boolean
  planEntries: PlanEntry[]
  /** Ordered list of events for interleaved rendering. */
  timeline: TimelineEntry[]
  /** True while session history is being replayed (session/load). */
  replaying: boolean
}

/** Per-pane state */
export interface PaneState {
  id: string           // unique pane ID
  tabs: string[]       // session IDs loaded as tabs in this pane
  activeTab: string    // which tab is currently showing
  width: number        // width as percentage (0-100)
}

interface AcpSessionStore {
  connectionState: ConnectionState
  connectionError: string | undefined
  /** Per-session data keyed by session ID. */
  sessionData: Record<string, SessionData>
  /** Panes with their tabs */
  panes: PaneState[]
  /** Currently focused pane (for keyboard routing). */
  activePaneId: string | undefined
  /** Slash commands advertised by the agent. */
  availableCommands: SlashCommand[]
  /** Session mode state (current mode + available modes). */
  sessionMode: SessionModeState | null
  /** Session IDs hidden by the user (x on tab). */
  hiddenSessions: string[]
  /** Available sessions from the agent. */
  sessions: Array<{ id: string; title?: string; created?: string }>
  /** Agent implementation info (name, version). */
  agentInfo: AgentInfo | null
  /** Agent capabilities from initialization. */
  agentCapabilities: AgentCapabilities | null
  /** Session config options from the agent. */
  configOptions: SessionConfigOption[]
}

interface AcpSessionActions {
  /** Send a text prompt to the agent in a specific session. */
  sendPrompt: (text: string, sessionId?: string) => void
  /** Respond to a permission request. */
  respondPermission: (requestId: number | string, optionId: string) => void
  /** Cancel the current prompt turn. */
  cancelPrompt: () => void
  /** Load a specific session by ID (adds as a tab to the active pane). */
  loadSession: (sessionId: string) => void
  /** Create a new session (adds tab to active pane). */
  newSession: () => void
  /** Set the active tab in a pane. */
  setActiveTab: (paneId: string, sessionId: string) => void
  /** Close a pane. */
  closePane: (paneId: string) => void
  /** Close a tab from a pane. */
  closeTab: (paneId: string, sessionId: string) => void
  /** Split the active pane (create a new empty pane). */
  splitPane: () => void
  /** Set the active pane. */
  setActivePane: (paneId: string) => void
  /** Move a tab from one pane to another. */
  moveTab: (sessionId: string, fromPaneId: string, toPaneId: string, insertBeforeSessionId?: string) => void
  /** Restore a hidden session (add it back as a tab in the active pane). */
  restoreSession: (sessionId: string) => void
  /** Get data for a specific session. */
  getSessionData: (sessionId: string) => SessionData
  /** Set pane width (percentage). */
  setPaneWidth: (paneId: string, width: number) => void
  /** Whether a session is actively receiving streamed text. */
  isSessionStreaming: (sessionId: string) => boolean
  /** Whether a session is buffering inside an unclosed code fence. */
  isSessionBufferingFence: (sessionId: string) => boolean
}

export type AcpSessionContext = AcpSessionStore & AcpSessionActions

const AcpCtx = createContext<AcpSessionContext>()

export function useAcpSession(): AcpSessionContext {
  const ctx = useContext(AcpCtx)
  if (!ctx) throw new Error("useAcpSession must be used inside AcpSessionProvider")
  return ctx
}

// ---------------------------------------------------------------------------
// Helper: extract text from a content block
// ---------------------------------------------------------------------------

function contentText(block: ContentBlock): string {
  if (block.type === "text") return block.text
  if (block.type === "image") return "[Image]"
  if (block.type === "audio") return "[Audio]"
  if (block.type === "resource_link") return `[Resource: ${block.name}]`
  if (block.type === "resource") return `[Embedded resource: ${block.resource.uri}]`
  return `[${(block as { type: string }).type}]`
}

/** Factory for creating empty session data. */
function emptySessionData(): SessionData {
  return {
    messages: [],
    toolCalls: {},
    pendingPermissions: [],
    prompting: false,
    planEntries: [],
    timeline: [],
    replaying: false,
  }
}

/** Sort sessions by created date. */
function sortSessionsByDate(
  sessions: Array<{ id: string; title?: string; created?: string }>,
  order: "asc" | "desc"
): Array<{ id: string; title?: string; created?: string }> {
  return [...sessions].sort((a, b) => {
    const ta = a.created ? new Date(a.created).getTime() : 0
    const tb = b.created ? new Date(b.created).getTime() : 0
    return order === "asc" ? ta - tb : tb - ta
  })
}

// toolContentText was previously used for flat text extraction from tool
// content blocks. Rendering is now handled by the Diff and Markdown
// shared components in agent.tsx.

// ---------------------------------------------------------------------------
// Provider
// ---------------------------------------------------------------------------


interface SavedLayout {
  panes: Array<{
    id: string
    tabs: string[]
    activeTab: string
    width: number
  }>
  activePaneId: string
}

export function AcpSessionProvider(props: ParentProps<{ podName: string }>) {
  // Module-level counters moved inside provider scope so they reset on remount.
  let msgCounter = 0
  let paneCounter = 0

  // ---------------------------------------------------------------------------
  // User message persistence
  // ---------------------------------------------------------------------------
  // Agents don't echo user_message_chunk during session replay, so user
  // messages are lost on page reload unless we persist them separately.

  function userMsgKey(sessionId: string): string {
    return `devaipod-user-msgs-${props.podName}-${sessionId}`
  }

  function saveUserMessage(sessionId: string, text: string) {
    try {
      const key = userMsgKey(sessionId)
      const existing: Array<{ text: string; timestamp: number }> =
        JSON.parse(sessionStorage.getItem(key) || "[]")
      existing.push({ text, timestamp: Date.now() })
      sessionStorage.setItem(key, JSON.stringify(existing))
    } catch {
      // Ignore storage errors
    }
  }

  function loadUserMessages(sessionId: string): Array<{ text: string; timestamp: number }> {
    try {
      const key = userMsgKey(sessionId)
      return JSON.parse(sessionStorage.getItem(key) || "[]")
    } catch {
      return []
    }
  }

  // Load hidden sessions from localStorage
  const hiddenKey = `devaipod-hidden-sessions-${props.podName}`
  const loadHidden = (): string[] => {
    try {
      const raw = localStorage.getItem(hiddenKey)
      return raw ? JSON.parse(raw) : []
    } catch { return [] }
  }

  const [store, setStore] = createStore<AcpSessionStore>({
    connectionState: "connecting",
    connectionError: undefined,
    sessionData: {},
    panes: [],
    activePaneId: undefined,
    hiddenSessions: loadHidden(),
    availableCommands: [],
    sessionMode: null,
    sessions: [],
    agentInfo: null,
    agentCapabilities: null,
    configOptions: [],
  })

  // Track which pane a hidden session came from (for restore)
  const hiddenFromPane: Record<string, string> = {}

  let ws: WebSocket | undefined
  let reconnectTimer: ReturnType<typeof setTimeout> | undefined
  const RECONNECT_DELAY_MS = 3000

  // Layout persistence
  const layoutKey = `devaipod-pane-layout-${props.podName}`
  const loadLayout = (): SavedLayout | null => {
    try {
      const raw = localStorage.getItem(layoutKey)
      return raw ? JSON.parse(raw) : null
    } catch { return null }
  }

  const saveLayout = () => {
    try {
      const layout: SavedLayout = {
        panes: store.panes.map((p) => ({
          id: p.id,
          tabs: p.tabs,
          activeTab: p.activeTab,
          width: p.width,
        })),
        activePaneId: store.activePaneId || "",
      }
      localStorage.setItem(layoutKey, JSON.stringify(layout))
    } catch {
      // Ignore save errors
    }
  }

  function buildWsUrl(): string {
    const proto = window.location.protocol === "https:" ? "wss:" : "ws:"
    const token = getAuthToken()
    let url = `${proto}//${window.location.host}/api/devaipod/pods/${encodeURIComponent(props.podName)}/pod-api/ws/events`
    if (token) url += `?token=${encodeURIComponent(token)}`
    return url
  }

  function sendWs(cmd: WsCommand) {
    if (ws?.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify(cmd))
    }
  }

  /** Clear session data and request a replay from the server. */
  /** Clear session data and request a replay from the server.
   *  IMPORTANT: This must call sendWs(), NOT itself. A prior bug had
   *  this calling reloadSession() recursively (infinite recursion). */
  // Queue of saved user messages to inject during session replay.
  // Keyed by session ID. Each entry is consumed as agent messages stream in.
  const replayUserMsgQueues: Record<string, Array<{ text: string; timestamp: number }>> = {}

  function reloadSession(sessionId: string) {
    // Load persisted user messages into a queue. They'll be injected
    // before the first agent_message_chunk of each turn during replay,
    // so conversations display in the correct interleaved order.
    replayUserMsgQueues[sessionId] = loadUserMessages(sessionId)
    fenceCounts[sessionId] = 0
    const data = emptySessionData()
    data.replaying = true
    setStore(
      produce((s) => {
        s.sessionData[sessionId] = data
      }),
    )
    sendWs({ type: "load_session", sessionId })

    // The ACP protocol has no "replay finished" signal. Use a debounce:
    // after events stop arriving for this session, mark replay as done.
    // Any new prompt from the user also clears the flag (see sendPrompt).
    if (replayTimers[sessionId]) clearTimeout(replayTimers[sessionId])
    replayTimers[sessionId] = setTimeout(() => {
      setStore(
        produce((s) => {
          if (s.sessionData[sessionId]) {
            s.sessionData[sessionId].replaying = false
          }
        }),
      )
    }, 500)
  }

  // Debounce timers for detecting end of session replay.
  const replayTimers: Record<string, ReturnType<typeof setTimeout>> = {}

  function connect() {
    if (ws) {
      ws.onclose = null
      ws.onerror = null
      ws.onmessage = null
      ws.close()
    }

    setStore("connectionState", "connecting")
    setStore("connectionError", undefined)

    const url = buildWsUrl()
    ws = new WebSocket(url)

    ws.onopen = () => {
      setStore("connectionState", "connected")
    }

    ws.onclose = () => {
      setStore("connectionState", "disconnected")
      scheduleReconnect()
    }

    ws.onerror = () => {
      setStore("connectionState", "error")
      setStore("connectionError", "WebSocket connection failed")
    }

    ws.onmessage = (event) => {
      try {
        const envelope: WsEnvelope = JSON.parse(event.data)
        handleEnvelope(envelope)
      } catch {
        // Ignore unparseable messages
      }
    }
  }

  function scheduleReconnect() {
    if (reconnectTimer) clearTimeout(reconnectTimer)
    reconnectTimer = setTimeout(connect, RECONNECT_DELAY_MS)
  }

  function handleEnvelope(envelope: WsEnvelope) {
    switch (envelope.type) {
      case "keepalive":
        // No-op, connection is alive
        break

      case "connection_status":
        if (envelope.status === "error") {
          setStore("connectionError", envelope.message)
        }
        break

      case "session_update":
        handleSessionUpdate(envelope.sessionId, envelope.update)
        break

      case "permission_request":
        handlePermissionRequest({
          requestId: envelope.requestId,
          sessionId: envelope.sessionId,
          toolCall: envelope.toolCall as Partial<ToolCall> & { toolCallId: string },
          options: (Array.isArray(envelope.options) ? envelope.options : []) as PermissionRequest["options"],
        })
        break

      case "prompt_response": {
        // Clear prompting for the session identified in the response envelope.
        setStore(
          produce((s) => {
            if (s.sessionData[envelope.sessionId]) {
              s.sessionData[envelope.sessionId].prompting = false
            }
          }),
        )
        break
      }

      case "session_list": {
        // The sessions payload may be { sessions: [...] } (from OpenCode)
        // or a flat array. Handle both.
        const raw = envelope.sessions
        const sessionArray = Array.isArray(raw)
          ? raw
          : Array.isArray(raw?.sessions)
            ? raw.sessions
            : []
        const sessions = sessionArray.map((s: { sessionId: string; title?: string; created?: string; updatedAt?: string }) => ({
          id: s.sessionId,
          title: s.title,
          created: s.created || s.updatedAt,
        }))
        setStore("sessions", sessions)

        // If we don't have any panes yet, try to restore layout or create default
        if (sessions.length > 0 && store.panes.length === 0) {
          const hidden = new Set(store.hiddenSessions)
          const visible = sessions.filter((ss) => !hidden.has(ss.id))
          if (visible.length === 0) {
            // All sessions hidden — clear hidden list and show all
            // (stale hidden IDs from old sessions shouldn't block everything)
            setStore("hiddenSessions", [])
            localStorage.removeItem(hiddenKey)
            // Re-run with no hidden filter
            const allSorted = sortSessionsByDate(sessions, "asc")
            const allNewest = sortSessionsByDate(sessions, "desc")[0]
            const paneId = `pane-${++paneCounter}`
            setStore(
              produce((s) => {
                s.panes = [{
                  id: paneId,
                  tabs: allSorted.map((ss) => ss.id),
                  activeTab: allNewest.id,
                  width: 100,
                }]
                s.activePaneId = paneId
              }),
            )
            reloadSession(allNewest.id)
            break
          }

          const savedLayout = loadLayout()
          const sessionIds = new Set(sessions.map((s) => s.id))

          // Check if saved layout is valid (all session IDs exist)
          if (
            savedLayout &&
            savedLayout.panes.length > 0 &&
            savedLayout.panes.every((p) =>
              p.tabs.every((tabId) => sessionIds.has(tabId))
            )
          ) {
            // Restore saved layout
            setStore(
              produce((s) => {
                s.panes = savedLayout.panes.map((p) => ({
                  id: p.id,
                  tabs: p.tabs,
                  activeTab: p.activeTab,
                  width: p.width,
                }))
                s.activePaneId = savedLayout.activePaneId
                // Update paneCounter to prevent ID collisions
                for (const p of savedLayout.panes) {
                  const num = parseInt(p.id.replace(/^pane-/, ""), 10)
                  if (!isNaN(num) && num >= paneCounter) {
                    paneCounter = num
                  }
                }
              }),
            )
            // Load each pane's active session history
            for (const p of savedLayout.panes) {
              if (p.activeTab) {
                reloadSession(p.activeTab)
              }
            }
          } else {
            // Create default layout: one pane with all visible sessions
            const sorted = sortSessionsByDate(visible, "asc")
            const newest = sortSessionsByDate(visible, "desc")[0]
            const paneId = `pane-${++paneCounter}`
            setStore(
              produce((s) => {
                s.panes = [
                  {
                    id: paneId,
                    tabs: sorted.map((ss) => ss.id),
                    activeTab: newest.id,
                    width: 100,
                  },
                ]
                s.activePaneId = paneId
              }),
            )
            // Load the active session's history
            reloadSession(newest.id)
          }
        }
        break
      }

      case "session_created": {
        // Add the new session as a tab to the active pane
        setStore(
          produce((s) => {
            const activePane = s.panes.find((p) => p.id === s.activePaneId)
            if (activePane) {
              if (!activePane.tabs.includes(envelope.sessionId)) {
                activePane.tabs.push(envelope.sessionId)
              }
              activePane.activeTab = envelope.sessionId
            } else {
              // No active pane, create one
              const paneId = `pane-${++paneCounter}`
              s.panes.push({
                id: paneId,
                tabs: [envelope.sessionId],
                activeTab: envelope.sessionId,
                width: 100,
              })
              s.activePaneId = paneId
            }
            // Store session metadata if provided
            if (envelope.modes) {
              s.sessionMode = envelope.modes
            }
            if (envelope.configOptions) {
              s.configOptions = envelope.configOptions
            }
          }),
        )
        // Refresh session list
        sendWs({ type: "list_sessions" })
        break
      }

      case "initialized": {
        // Store agent info and capabilities from the initialization handshake
        setStore(
          produce((s) => {
            if (envelope.agentInfo) {
              s.agentInfo = envelope.agentInfo
            }
            if (envelope.capabilities) {
              s.agentCapabilities = envelope.capabilities
            }
          }),
        )
        break
      }
    }
  }

  function handleSessionUpdate(sessionId: string, update: WsEnvelope extends { type: "session_update" } ? WsEnvelope["update"] : never) {
    // Initialize session data if it doesn't exist
    setStore(
      produce((s) => {
        if (!s.sessionData[sessionId]) {
          s.sessionData[sessionId] = emptySessionData()
        }
      }),
    )

    // During replay, reset the debounce timer on each event so we
    // detect when the replay stream stops (no "replay done" signal in ACP).
    if (store.sessionData[sessionId]?.replaying && replayTimers[sessionId]) {
      clearTimeout(replayTimers[sessionId])
      replayTimers[sessionId] = setTimeout(() => {
        setStore(
          produce((s) => {
            if (s.sessionData[sessionId]) {
              s.sessionData[sessionId].replaying = false
            }
          }),
        )
        // Reset fence counter after replay so it doesn't carry stale state.
        fenceCounts[sessionId] = 0
      }, 500)
    }

    // During replay, write directly to the store (no buffering/fence
    // detection needed for historical content). This also prevents the
    // fence counter from going odd and showing "Writing code..." flash.
    const isReplaying = store.sessionData[sessionId]?.replaying ?? false

    switch (update.sessionUpdate) {
      case "agent_message_chunk": {
        const text = contentText(update.content)
        if (!text) break
        if (isReplaying) {
          appendMessageDirect(sessionId, "assistant", text)
        } else {
          appendOrUpdateMessage(sessionId, "assistant", text)
        }
        break
      }

      case "user_message_chunk": {
        const text = contentText(update.content)
        if (!text) break
        if (isReplaying) {
          appendMessageDirect(sessionId, "user", text)
        } else {
          appendOrUpdateMessage(sessionId, "user", text)
        }
        break
      }

      case "agent_thought_chunk": {
        const text = contentText(update.content)
        if (!text) break
        if (isReplaying) {
          appendMessageDirect(sessionId, "thought", text)
        } else {
          appendOrUpdateMessage(sessionId, "thought", text)
        }
        break
      }

      case "tool_call": {
        // Force-flush buffered text before the tool call to keep timeline order.
        if (chunkBuffers[sessionId]?.text) {
          if (chunkTimers[sessionId]) {
            clearTimeout(chunkTimers[sessionId])
            delete chunkTimers[sessionId]
          }
          flushChunkBuffer(sessionId, true)
        }
        setStore(
          produce((s) => {
            if (!s.sessionData[sessionId]) return
            s.sessionData[sessionId].toolCalls[update.toolCallId] = {
              toolCallId: update.toolCallId,
              title: update.title,
              kind: update.kind,
              status: update.status ?? "pending",
              content: update.content,
              locations: update.locations,
              rawInput: update.rawInput,
            }
            // Only add to timeline if this is a new tool call (not a duplicate)
            if (!s.sessionData[sessionId].timeline.some(
              (e) => e.kind === "toolCall" && e.id === update.toolCallId
            )) {
              s.sessionData[sessionId].timeline.push({
                kind: "toolCall",
                id: update.toolCallId,
              })
            }
          }),
        )
        break
      }

      case "tool_call_update": {
        setStore(
          produce((s) => {
            if (!s.sessionData[sessionId]) return
            const existing = s.sessionData[sessionId].toolCalls[update.toolCallId]
            if (existing) {
              if (update.kind) existing.kind = update.kind
              if (update.status) existing.status = update.status as ToolCallStatus
              if (update.title) existing.title = update.title
              if (update.content) existing.content = update.content as Array<ToolCallContent | ToolCallDiff | ToolCallTerminal>
              if (update.locations) existing.locations = update.locations
              if (update.rawInput) existing.rawInput = update.rawInput
              if (update.rawOutput) existing.rawOutput = update.rawOutput
            }
          }),
        )
        break
      }

      case "plan":
        setStore(
          produce((s) => {
            if (!s.sessionData[sessionId]) return
            s.sessionData[sessionId].planEntries = update.entries
          }),
        )
        break

      case "available_commands_update":
        setStore("availableCommands", update.availableCommands)
        break

      case "current_mode_update":
        setStore(
          produce((s) => {
            if (s.sessionMode) {
              s.sessionMode.currentModeId = update.currentModeId
            } else {
              s.sessionMode = {
                currentModeId: update.currentModeId,
                availableModes: [],
              }
            }
          }),
        )
        break

      case "config_option_update":
        setStore("configOptions", update.configOptions)
        break

      case "session_info_update": {
        // Update session title if provided
        if (update.title !== undefined) {
          setStore(
            produce((s) => {
              const session = s.sessions.find((ss) => ss.id === sessionId)
              if (session) {
                session.title = update.title ?? undefined
              }
            }),
          )
        }
        break
      }
    }
  }

  /**
   * Append text to the last message if it has the same role (streaming),
   * or create a new message.
   *
   * During session replay, agents don't echo user messages. Before starting
   * a new assistant turn, inject the next saved user message from the
   * replay queue so the conversation displays in the correct order.
   *
   * Streaming chunks are buffered and flushed to the store periodically
   * (every CHUNK_FLUSH_MS) to reduce DOM thrashing from per-token updates.
   */
  /**
   * Streaming chunks are buffered and flushed to the store when the
   * stream pauses for CHUNK_FLUSH_MS. This prevents partial markdown
   * (e.g. half a code fence or diagram) from being rendered mid-stream.
   *
   * Uses path-based store setters for text updates to ensure SolidJS
   * fine-grained reactivity triggers Markdown re-renders on flush.
   */
  /**
   * Streaming chunks are buffered and flushed to the store. The buffer
   * flushes when:
   *   - Tokens stop for CHUNK_FLUSH_MS AND no unclosed code fence
   *   - A tool call arrives (explicit flush)
   *   - Role changes
   *
   * If the buffered text contains an unclosed code fence (odd number
   * of ``` delimiters), flushing is suppressed until the fence closes
   * or FENCE_FLUSH_MS elapses (safety valve to avoid infinite buffering).
   */
  const CHUNK_FLUSH_MS = 300       // Normal text: flush after 300ms pause
  const FENCE_FLUSH_MS = 5000      // Inside code fence: hold until closed
  const chunkBuffers: Record<string, { role: AcpMessage["role"]; text: string; startTime: number }> = {}
  const chunkTimers: Record<string, ReturnType<typeof setTimeout>> = {}
  // Track total fence count per session across all flushes.
  // Odd = inside a fence, even = outside.
  const fenceCounts: Record<string, number> = {}

  // Reactive signal so the UI can show streaming/buffering indicators.
  const [streamingSessionIds, setStreamingSessionIds] = createSignal<Set<string>>(new Set())
  const [bufferingFenceSessionIds, setBufferingFenceSessionIds] = createSignal<Set<string>>(new Set())

  function updateStreamingState(sessionId: string) {
    const buf = chunkBuffers[sessionId]
    const isStreaming = !!buf?.text
    const isFence = isStreaming && isInsideFence(sessionId, buf!.text)

    setStreamingSessionIds((prev) => {
      const next = new Set(prev)
      if (isStreaming) next.add(sessionId); else next.delete(sessionId)
      return next
    })
    setBufferingFenceSessionIds((prev) => {
      const next = new Set(prev)
      if (isFence) next.add(sessionId); else next.delete(sessionId)
      return next
    })
  }

  /** Count ``` fence delimiters in a string.
   *  A fence delimiter is ``` at the start of a line, optionally followed
   *  by a language tag, with nothing else on the line. */
  function countFences(text: string): number {
    const matches = text.match(/^```[^\S\n]*\S*[^\S\n]*$/gm)
    return matches ? matches.length : 0
  }

  /** Whether the session is currently inside an unclosed code fence.
   *  Uses running counter from prior flushes + fences in current buffer. */
  function isInsideFence(sessionId: string, bufferText: string): boolean {
    const prior = fenceCounts[sessionId] || 0
    const bufferFences = countFences(bufferText)
    return (prior + bufferFences) % 2 !== 0
  }

  function flushChunkBuffer(sessionId: string, force?: boolean) {
    const buf = chunkBuffers[sessionId]
    if (!buf || !buf.text) return

    const elapsed = Date.now() - buf.startTime
    if (!force && isInsideFence(sessionId, buf.text) && elapsed < FENCE_FLUSH_MS) {
      if (chunkTimers[sessionId]) clearTimeout(chunkTimers[sessionId])
      chunkTimers[sessionId] = setTimeout(() => {
        delete chunkTimers[sessionId]
        flushChunkBuffer(sessionId)
      }, CHUNK_FLUSH_MS)
      updateStreamingState(sessionId)
      return
    }

    const { role, text } = buf
    // Update running fence count with fences in the flushed text.
    fenceCounts[sessionId] = (fenceCounts[sessionId] || 0) + countFences(text)
    buf.text = ""
    buf.startTime = Date.now()
    updateStreamingState(sessionId)

    const sd = store.sessionData[sessionId]
    if (!sd) return

    const messages = sd.messages
    const last = messages[messages.length - 1]
    const timeline = sd.timeline
    const lastTimelineEntry = timeline[timeline.length - 1]
    const toolCallInterrupted = lastTimelineEntry?.kind === "toolCall"

    if (last && last.role === role && !toolCallInterrupted) {
      const idx = messages.length - 1
      setStore("sessionData", sessionId, "messages", idx, "text", (prev) => prev + text)
    } else {
      const id = `msg-${++msgCounter}`
      setStore(
        produce((s) => {
          s.sessionData[sessionId].messages.push({
            id,
            role,
            text,
            timestamp: Date.now(),
          })
          s.sessionData[sessionId].timeline.push({ kind: "message", id })
        }),
      )
    }
  }

  /** Direct store append -- no buffering, no fence detection.
   *  Used during replay where content is historical and complete. */
  function appendMessageDirect(sessionId: string, role: AcpMessage["role"], text: string) {
    const sd = store.sessionData[sessionId]
    if (!sd) return
    const messages = sd.messages
    const last = messages[messages.length - 1]
    const timeline = sd.timeline
    const lastTimelineEntry = timeline[timeline.length - 1]
    const toolCallInterrupted = lastTimelineEntry?.kind === "toolCall"

    if (last && last.role === role && !toolCallInterrupted) {
      const idx = messages.length - 1
      setStore("sessionData", sessionId, "messages", idx, "text", (prev) => prev + text)
    } else {
      const id = `msg-${++msgCounter}`
      setStore(
        produce((s) => {
          s.sessionData[sessionId].messages.push({ id, role, text, timestamp: Date.now() })
          s.sessionData[sessionId].timeline.push({ kind: "message", id })
        }),
      )
    }
  }

  function appendOrUpdateMessage(sessionId: string, role: AcpMessage["role"], text: string) {
    // Inject saved user messages synchronously (not buffered).
    setStore(
      produce((s) => {
        if (!s.sessionData[sessionId]) {
          s.sessionData[sessionId] = emptySessionData()
        }
        const messages = s.sessionData[sessionId].messages
        const last = messages[messages.length - 1]

        if (role !== "user" && (!last || last.role !== role)) {
          const queue = replayUserMsgQueues[sessionId]
          if (queue && queue.length > 0) {
            const saved = queue.shift()!
            const savedId = `msg-${++msgCounter}`
            messages.push({
              id: savedId,
              role: "user",
              text: saved.text,
              timestamp: saved.timestamp,
            })
            s.sessionData[sessionId].timeline.push({ kind: "message", id: savedId })
          }
        }
      }),
    )

    // Buffer chunks. Flush previous buffer if role changed.
    const buf = chunkBuffers[sessionId]
    if (buf && buf.role === role) {
      buf.text += text
      buf.startTime = Date.now()  // Reset so safety valve measures from last chunk
    } else {
      if (buf) flushChunkBuffer(sessionId, true)
      chunkBuffers[sessionId] = { role, text, startTime: Date.now() }
    }

    // Debounce: reset timer on each chunk.
    if (chunkTimers[sessionId]) clearTimeout(chunkTimers[sessionId])
    chunkTimers[sessionId] = setTimeout(() => {
      delete chunkTimers[sessionId]
      flushChunkBuffer(sessionId)
    }, CHUNK_FLUSH_MS)
    updateStreamingState(sessionId)
  }

  /** Whether a session is actively receiving streamed text. */
  function isSessionStreaming(sessionId: string): boolean {
    return streamingSessionIds().has(sessionId)
  }

  /** Whether a session is buffering inside an unclosed code fence. */
  function isSessionBufferingFence(sessionId: string): boolean {
    return bufferingFenceSessionIds().has(sessionId)
  }

  function handlePermissionRequest(request: PermissionRequest) {
    // Permission requests are handled by the backend's auto_approve AtomicBool.
    // If they reach the frontend, they need manual approval.
    // Show in UI for manual approval - route to active pane's active tab
    const activePane = store.panes.find((p) => p.id === store.activePaneId)
    if (!activePane) return
    const sessionId = activePane.activeTab

    setStore(
      produce((s) => {
        if (!s.sessionData[sessionId]) {
          s.sessionData[sessionId] = emptySessionData()
        }
        s.sessionData[sessionId].pendingPermissions.push(request)
      }),
    )
  }

  // -- Public actions -------------------------------------------------------

  function sendPrompt(text: string, sessionId?: string) {
    if (!text.trim()) return

    let sid = sessionId
    if (!sid) {
      // Default to active pane's active tab
      const activePane = store.panes.find((p) => p.id === store.activePaneId)
      if (!activePane) return
      sid = activePane.activeTab
    }

    // Flush any remaining replay queue and mark replay as done
    // (user is actively interacting).
    delete replayUserMsgQueues[sid!]
    fenceCounts[sid!] = 0
    if (replayTimers[sid!]) {
      clearTimeout(replayTimers[sid!])
      delete replayTimers[sid!]
    }
    setStore(
      produce((s) => {
        if (s.sessionData[sid!]) {
          s.sessionData[sid!].replaying = false
        }
      }),
    )

    // Add user message to local display and persist to sessionStorage
    // so it survives session replay (agents don't echo user messages).
    setStore(
      produce((s) => {
        if (!s.sessionData[sid!]) {
          s.sessionData[sid!] = emptySessionData()
        }
        const userMsgId = `msg-${++msgCounter}`
        s.sessionData[sid!].messages.push({
          id: userMsgId,
          role: "user",
          text,
          timestamp: Date.now(),
        })
        s.sessionData[sid!].timeline.push({ kind: "message", id: userMsgId })
        s.sessionData[sid!].prompting = true
      }),
    )
    saveUserMessage(sid!, text)

    sendWs({
      type: "send_prompt",
      sessionId: sid,
      prompt: [{ type: "text", text }],
    })
  }

  function respondPermission(requestId: number | string, optionId: string) {
    sendWs({
      type: "permission_response",
      requestId,
      optionId,
    })

    // Remove from pending (check all sessions)
    setStore(
      produce((s) => {
        for (const sessionId in s.sessionData) {
          s.sessionData[sessionId].pendingPermissions = s.sessionData[sessionId].pendingPermissions.filter(
            (p) => p.requestId !== requestId,
          )
        }
      }),
    )
  }

  function cancelPrompt() {
    const activePane = store.panes.find((p) => p.id === store.activePaneId)
    if (activePane) {
      sendWs({
        type: "cancel_prompt",
        sessionId: activePane.activeTab,
      })
      setStore(
        produce((s) => {
          if (s.sessionData[activePane.activeTab]) {
            s.sessionData[activePane.activeTab].prompting = false
          }
        }),
      )
    }
  }


  // Save layout whenever panes change
  createEffect(() => {
    // Track panes to trigger effect
    const _ = store.panes
    if (store.panes.length > 0) {
      saveLayout()
    }
  })

  // Connect on mount
  connect()

  onCleanup(() => {
    if (reconnectTimer) clearTimeout(reconnectTimer)
    if (ws) {
      ws.onclose = null
      ws.close()
    }
  })

  function loadSession(sessionId: string) {
    setStore(
      produce((s) => {
        const activePane = s.panes.find((p) => p.id === s.activePaneId)
        if (activePane) {
          // Add to active pane's tabs if not already there
          if (!activePane.tabs.includes(sessionId)) {
            activePane.tabs.push(sessionId)
          }
          activePane.activeTab = sessionId
        } else {
          // No active pane, create one
          const paneId = `pane-${++paneCounter}`
          s.panes.push({
            id: paneId,
            tabs: [sessionId],
            activeTab: sessionId,
            width: 100,
          })
          s.activePaneId = paneId
        }
      }),
    )
    // reloadSession clears sessionData, so don't clear it here (double-clear)
    reloadSession(sessionId)
  }

  function newSession() {
    sendWs({ type: "new_session" })
    // The session_created event will handle adding to panes
  }

  function setActiveTab(paneId: string, sessionId: string) {
    setStore(
      produce((s) => {
        const pane = s.panes.find((p) => p.id === paneId)
        if (pane && pane.tabs.includes(sessionId)) {
          pane.activeTab = sessionId
        }
      }),
    )
    // Load session history if we don't have data for it yet
    if (!store.sessionData[sessionId] || store.sessionData[sessionId].messages.length === 0) {
      reloadSession(sessionId)
    }
  }

  function closePane(paneId: string) {
    setStore(
      produce((s) => {
        const paneIdx = s.panes.findIndex((p) => p.id === paneId)
        if (paneIdx >= 0) {
          s.panes.splice(paneIdx, 1)
          // If closing the active pane, switch to next available
          if (s.activePaneId === paneId && s.panes.length > 0) {
            s.activePaneId = s.panes[0].id
          }
          // Redistribute widths evenly
          if (s.panes.length > 0) {
            const newWidth = 100 / s.panes.length
            for (const pane of s.panes) {
              pane.width = newWidth
            }
          }
        }
      }),
    )
  }

  function closeTab(paneId: string, sessionId: string) {
    // Track source pane for restore
    hiddenFromPane[sessionId] = paneId

    // Mark as hidden and persist
    setStore(
      produce((s) => {
        if (!s.hiddenSessions.includes(sessionId)) {
          s.hiddenSessions.push(sessionId)
        }
      }),
    )
    localStorage.setItem(hiddenKey, JSON.stringify(store.hiddenSessions))

    setStore(
      produce((s) => {
        const pane = s.panes.find((p) => p.id === paneId)
        if (!pane) return

        const tabIdx = pane.tabs.indexOf(sessionId)
        if (tabIdx < 0) return

        pane.tabs.splice(tabIdx, 1)

        // If no tabs left, remove the pane and redistribute widths
        if (pane.tabs.length === 0) {
          const paneIdx = s.panes.findIndex((p) => p.id === paneId)
          s.panes.splice(paneIdx, 1)
          if (s.activePaneId === paneId && s.panes.length > 0) {
            s.activePaneId = s.panes[0].id
          }
          if (s.panes.length > 0) {
            const newWidth = 100 / s.panes.length
            for (const p of s.panes) {
              p.width = newWidth
            }
          }
        } else {
          if (pane.activeTab === sessionId) {
            pane.activeTab = pane.tabs[Math.max(0, tabIdx - 1)]
          }
        }
      }),
    )
  }

  function splitPane() {
    setStore(
      produce((s) => {
        // Distribute width evenly across all panes
        const newPaneCount = s.panes.length + 1
        const newWidth = 100 / newPaneCount
        for (const pane of s.panes) {
          pane.width = newWidth
        }
        const paneId = `pane-${++paneCounter}`
        s.panes.push({
          id: paneId,
          tabs: [],
          activeTab: "",
          width: newWidth,
        })
        s.activePaneId = paneId
      }),
    )
  }

  function setActivePane(paneId: string) {
    setStore("activePaneId", paneId)
  }

  function moveTab(sessionId: string, fromPaneId: string, toPaneId: string, insertBeforeSessionId?: string) {
    // Same pane: reorder
    if (fromPaneId === toPaneId) {
      if (!insertBeforeSessionId) return
      setStore(
        produce((s) => {
          const pane = s.panes.find((p) => p.id === fromPaneId)
          if (!pane) return
          const fromIdx = pane.tabs.indexOf(sessionId)
          if (fromIdx < 0) return
          pane.tabs.splice(fromIdx, 1)
          // "__end__" means append to the end
          const toIdx = insertBeforeSessionId === "__end__"
            ? pane.tabs.length
            : pane.tabs.indexOf(insertBeforeSessionId)
          pane.tabs.splice(toIdx >= 0 ? toIdx : pane.tabs.length, 0, sessionId)
        }),
      )
      return
    }
    setStore(
      produce((s) => {
        const from = s.panes.find((p) => p.id === fromPaneId)
        const to = s.panes.find((p) => p.id === toPaneId)
        if (!from || !to) return

        // Remove from source pane
        from.tabs = from.tabs.filter((t) => t !== sessionId)
        if (from.activeTab === sessionId) {
          from.activeTab = from.tabs[0] || ""
        }

        // Add to target pane
        if (!to.tabs.includes(sessionId)) {
          to.tabs.push(sessionId)
        }
        to.activeTab = sessionId

        // Remove empty source pane and redistribute widths
        if (from.tabs.length === 0) {
          s.panes = s.panes.filter((p) => p.id !== fromPaneId)
          if (s.activePaneId === fromPaneId) {
            s.activePaneId = toPaneId
          }
          if (s.panes.length > 0) {
            const newWidth = 100 / s.panes.length
            for (const p of s.panes) {
              p.width = newWidth
            }
          }
        }
      }),
    )
  }

  function restoreSession(sessionId: string) {
    // Remove from hidden list and persist
    setStore(
      produce((s) => {
        s.hiddenSessions = s.hiddenSessions.filter((id) => id !== sessionId)
      }),
    )
    localStorage.setItem(hiddenKey, JSON.stringify(store.hiddenSessions))

    // Restore to the pane it was hidden from, or first pane, or create new
    const sourcePaneId = hiddenFromPane[sessionId]
    delete hiddenFromPane[sessionId]

    setStore(
      produce((s) => {
        // Try source pane first, then first pane
        const targetPane = s.panes.find((p) => p.id === sourcePaneId)
          || s.panes[0]
        if (targetPane) {
          if (!targetPane.tabs.includes(sessionId)) {
            targetPane.tabs.push(sessionId)
          }
          targetPane.activeTab = sessionId
        } else {
          const paneId = `pane-${++paneCounter}`
          s.panes.push({
            id: paneId,
            tabs: [sessionId],
            activeTab: sessionId,
            width: 100,
          })
          s.activePaneId = paneId
        }
      }),
    )
    // Load the session's history
    reloadSession(sessionId)
  }

  function getSessionData(sessionId: string): SessionData {
    // Ensure session data lives in the store so SolidJS can track
    // reactive updates. Returning a detached fallback object breaks
    // reactivity because <For> sees a new array reference each call
    // and never subscribes to the store path.
    if (!store.sessionData[sessionId]) {
      setStore(
        produce((s) => {
          if (!s.sessionData[sessionId]) {
            s.sessionData[sessionId] = emptySessionData()
          }
        }),
      )
    }
    return store.sessionData[sessionId]
  }

  function setPaneWidth(paneId: string, width: number) {
    setStore(
      produce((s) => {
        const pane = s.panes.find((p) => p.id === paneId)
        if (pane) {
          pane.width = width
        }
      }),
    )
  }

  const value: AcpSessionContext = {
    get connectionState() { return store.connectionState },
    get connectionError() { return store.connectionError },
    get sessionData() { return store.sessionData },
    get availableCommands() { return store.availableCommands },
    get sessionMode() { return store.sessionMode },
    get sessions() { return store.sessions },
    get panes() { return store.panes },
    get activePaneId() { return store.activePaneId },
    get hiddenSessions() { return store.hiddenSessions },
    get agentInfo() { return store.agentInfo },
    get agentCapabilities() { return store.agentCapabilities },
    get configOptions() { return store.configOptions },
    // Backwards compat: getters that point to active pane's active tab's session data
    get messages() {
      const activePane = store.panes.find((p) => p.id === store.activePaneId)
      const sid = activePane?.activeTab
      return sid ? (store.sessionData[sid]?.messages ?? []) : []
    },
    get toolCalls() {
      const activePane = store.panes.find((p) => p.id === store.activePaneId)
      const sid = activePane?.activeTab
      return sid ? (store.sessionData[sid]?.toolCalls ?? {}) : {}
    },
    get pendingPermissions() {
      const activePane = store.panes.find((p) => p.id === store.activePaneId)
      const sid = activePane?.activeTab
      return sid ? (store.sessionData[sid]?.pendingPermissions ?? []) : []
    },
    get prompting() {
      const activePane = store.panes.find((p) => p.id === store.activePaneId)
      const sid = activePane?.activeTab
      return sid ? (store.sessionData[sid]?.prompting ?? false) : false
    },
    get sessionId() {
      const activePane = store.panes.find((p) => p.id === store.activePaneId)
      return activePane?.activeTab
    },
    sendPrompt,
    respondPermission,
    cancelPrompt,
    loadSession,
    newSession,
    setActiveTab,
    closePane,
    closeTab,
    splitPane,
    setActivePane,
    moveTab,
    restoreSession,
    getSessionData,
    setPaneWidth,
    isSessionStreaming,
    isSessionBufferingFence,
  }

  return <AcpCtx.Provider value={value}>{props.children}</AcpCtx.Provider>
}

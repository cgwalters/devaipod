/**
 * ACP (Agent Client Protocol) types for the devaipod frontend.
 *
 * These types model the subset of ACP protocol messages that the frontend
 * needs to render: session/update notifications (text, tool calls, plans,
 * permission requests) forwarded by pod-api over WebSocket.
 *
 * Pod-api wraps each ACP notification in an envelope with a `type` discriminator
 * so the frontend can distinguish keepalives, connection status, and ACP events.
 */

// ---------------------------------------------------------------------------
// ACP content blocks (subset of MCP ContentBlock)
// ---------------------------------------------------------------------------

export interface TextContent {
  type: "text"
  text: string
}

export interface ImageContent {
  type: "image"
  mimeType: string
  data: string
  uri?: string
}

export interface AudioContent {
  type: "audio"
  mimeType: string
  data: string
}

export interface ResourceLinkContent {
  type: "resource_link"
  name: string
  uri: string
  description?: string
  mimeType?: string
  size?: number
  title?: string
}

export interface EmbeddedResourceContent {
  type: "resource"
  resource: {
    uri: string
    mimeType?: string
    text?: string
    blob?: string
  }
}

export type ContentBlock =
  | TextContent
  | ImageContent
  | AudioContent
  | ResourceLinkContent
  | EmbeddedResourceContent

// ---------------------------------------------------------------------------
// Tool call types
// ---------------------------------------------------------------------------

export type ToolKind =
  | "read"
  | "edit"
  | "delete"
  | "move"
  | "search"
  | "execute"
  | "think"
  | "fetch"
  | "switch_mode"
  | "other"

export type ToolCallStatus =
  | "pending"
  | "in_progress"
  | "completed"
  | "failed"
  | "cancelled"

export interface ToolCallContent {
  type: "content"
  content: ContentBlock
}

export interface ToolCallDiff {
  type: "diff"
  path: string
  oldText?: string
  newText: string
}

export interface ToolCallTerminal {
  type: "terminal"
  terminalId: string
}

export interface ToolCallLocation {
  path: string
  line?: number
}

export interface ToolCall {
  toolCallId: string
  title: string
  kind?: ToolKind
  status: ToolCallStatus
  content?: Array<ToolCallContent | ToolCallDiff | ToolCallTerminal>
  locations?: ToolCallLocation[]
  rawInput?: Record<string, unknown>
  rawOutput?: Record<string, unknown>
}

// ---------------------------------------------------------------------------
// Permission request
// ---------------------------------------------------------------------------

export type PermissionOptionKind =
  | "allow_once"
  | "allow_always"
  | "reject_once"
  | "reject_always"

export interface PermissionOption {
  optionId: string
  name: string
  kind: PermissionOptionKind
}

export interface PermissionRequest {
  /** JSON-RPC request ID from the agent; pod-api needs this to send the response. */
  requestId: number | string
  sessionId: string
  toolCall: Partial<ToolCall> & { toolCallId: string }
  options: PermissionOption[]
}

// ---------------------------------------------------------------------------
// Plan entries
// ---------------------------------------------------------------------------

export interface PlanEntry {
  content: string
  priority?: "high" | "medium" | "low"
  status?: "pending" | "in_progress" | "completed" | "failed"
}

// ---------------------------------------------------------------------------
// Slash commands and session modes
// ---------------------------------------------------------------------------

/** Slash command advertised by the agent. */
export interface SlashCommand {
  name: string
  description: string
  input?: {
    hint: string
  }
}

/** Session mode available from the agent. */
export interface SessionMode {
  id: string
  name: string
  description?: string
}

/** Tracked state for session modes. */
export interface SessionModeState {
  currentModeId: string
  availableModes: SessionMode[]
}

// ---------------------------------------------------------------------------
// Session config options
// ---------------------------------------------------------------------------

export interface SessionConfigSelectOption {
  value: string
  name: string
  description?: string
}

export interface SessionConfigOption {
  id: string
  name: string
  description?: string
  category?: "mode" | "model" | "thought_level" | string
  type: "select"
  currentValue: string
  options: SessionConfigSelectOption[] | Array<{ name: string; options: SessionConfigSelectOption[] }>
}

// ---------------------------------------------------------------------------
// Agent capabilities and info
// ---------------------------------------------------------------------------

export interface AgentInfo {
  name: string
  title?: string
  version: string
}

export interface AgentCapabilities {
  loadSession: boolean
  promptCapabilities: {
    image: boolean
    audio: boolean
    embeddedContext: boolean
  }
  mcpCapabilities: Record<string, unknown>
  sessionCapabilities: Record<string, unknown>
}

// ---------------------------------------------------------------------------
// Session update union (from session/update notifications)
// ---------------------------------------------------------------------------

export interface AgentMessageChunk {
  sessionUpdate: "agent_message_chunk"
  content: ContentBlock
}

export interface UserMessageChunk {
  sessionUpdate: "user_message_chunk"
  content: ContentBlock
}

export interface ThoughtChunk {
  sessionUpdate: "agent_thought_chunk"
  content: ContentBlock
}

export interface ToolCallUpdate {
  sessionUpdate: "tool_call"
  toolCallId: string
  title: string
  kind?: ToolKind
  status?: ToolCallStatus
  content?: Array<ToolCallContent | ToolCallDiff | ToolCallTerminal>
  locations?: ToolCallLocation[]
  rawInput?: Record<string, unknown>
}

export interface ToolCallStatusUpdate {
  sessionUpdate: "tool_call_update"
  toolCallId: string
  kind?: ToolKind
  status?: ToolCallStatus
  title?: string
  content?: Array<ToolCallContent | ToolCallDiff | ToolCallTerminal>
  locations?: ToolCallLocation[]
  rawInput?: Record<string, unknown>
  rawOutput?: Record<string, unknown>
}

export interface PlanUpdate {
  sessionUpdate: "plan"
  entries: PlanEntry[]
}

/** Available commands update notification. */
export interface AvailableCommandsUpdate {
  sessionUpdate: "available_commands_update"
  availableCommands: SlashCommand[]
}

/** Current mode update notification. */
export interface CurrentModeUpdate {
  sessionUpdate: "current_mode_update"
  currentModeId: string
}

/** Config option update notification. */
export interface ConfigOptionUpdate {
  sessionUpdate: "config_option_update"
  configOptions: SessionConfigOption[]
}

/** Session info update notification (title changes, etc.). */
export interface SessionInfoUpdate {
  sessionUpdate: "session_info_update"
  title?: string | null
  updatedAt?: string | null
}

export type SessionUpdate =
  | AgentMessageChunk
  | UserMessageChunk
  | ThoughtChunk
  | ToolCallUpdate
  | ToolCallStatusUpdate
  | PlanUpdate
  | AvailableCommandsUpdate
  | CurrentModeUpdate
  | ConfigOptionUpdate
  | SessionInfoUpdate

// ---------------------------------------------------------------------------
// WebSocket envelope (pod-api → frontend)
// ---------------------------------------------------------------------------

/** Keepalive ping from pod-api. */
export interface WsKeepalive {
  type: "keepalive"
}

/** ACP session/update notification forwarded by pod-api. */
export interface WsSessionUpdate {
  type: "session_update"
  sessionId: string
  update: SessionUpdate
}

/** ACP permission request forwarded by pod-api.
 * Fields are flattened from AcpEvent::PermissionRequest (not nested in a `request` object).
 */
export interface WsPermissionRequest {
  type: "permission_request"
  requestId: number | string
  sessionId: string
  toolCall: Record<string, unknown>
  options: PermissionOption[] | Record<string, unknown>
}

/** Connection status change (pod-api → frontend). */
export interface WsConnectionStatus {
  type: "connection_status"
  status: "connected" | "disconnected" | "error"
  message?: string
}

/** Prompt response (turn completed). */
export interface WsPromptResponse {
  type: "prompt_response"
  sessionId: string
  stopReason: "end_turn" | "max_tokens" | "max_turn_requests" | "refusal" | "cancelled"
}

/** Session list response. */
export interface WsSessionList {
  type: "session_list"
  sessions: Array<{
    sessionId: string
    title?: string
    created?: string
  }>
}

export interface WsSessionCreated {
  type: "session_created"
  sessionId: string
  modes?: SessionModeState
  configOptions?: SessionConfigOption[]
}

/** Agent initialization completed. */
export interface WsInitialized {
  type: "initialized"
  agentInfo?: AgentInfo
  capabilities?: AgentCapabilities
}

export type WsEnvelope =
  | WsKeepalive
  | WsSessionUpdate
  | WsPermissionRequest
  | WsConnectionStatus
  | WsPromptResponse
  | WsSessionList
  | WsSessionCreated
  | WsInitialized

// ---------------------------------------------------------------------------
// Frontend → pod-api commands (over the same WebSocket)
// ---------------------------------------------------------------------------

/** Send a prompt to the agent. */
export interface WsSendPrompt {
  type: "send_prompt"
  sessionId?: string
  prompt: ContentBlock[]
}

/** Respond to a permission request. */
export interface WsPermissionResponse {
  type: "permission_response"
  requestId: number | string
  optionId: string
}

/** Cancel the current prompt turn. */
export interface WsCancelPrompt {
  type: "cancel_prompt"
  sessionId: string
}

/** List all sessions. */
export interface WsListSessions {
  type: "list_sessions"
}

/** Load a specific session. */
export interface WsLoadSession {
  type: "load_session"
  sessionId: string
}

/** Create a new session. */
export interface WsNewSession {
  type: "new_session"
}

export type WsCommand =
  | WsSendPrompt
  | WsPermissionResponse
  | WsCancelPrompt
  | WsListSessions
  | WsLoadSession
  | WsNewSession

// ---------------------------------------------------------------------------
// UI-level message model (accumulated from events)
// ---------------------------------------------------------------------------

export type MessageRole = "user" | "assistant" | "thought"

export interface AcpMessage {
  id: string
  role: MessageRole
  text: string
  timestamp: number
}

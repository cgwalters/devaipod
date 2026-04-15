import "@/index.css"
import { ErrorBoundary, Show, Suspense, lazy, type JSX, type ParentProps } from "solid-js"
import { Router, Route, Navigate } from "@solidjs/router"
import { MetaProvider } from "@solidjs/meta"
import { Font } from "@opencode-ai/ui/font"
import { MarkedProvider } from "@opencode-ai/ui/context/marked"
import { DiffComponentProvider } from "@opencode-ai/ui/context/diff"
import { CodeComponentProvider } from "@opencode-ai/ui/context/code"
import { I18nProvider } from "@opencode-ai/ui/context"
import { Diff } from "@opencode-ai/ui/diff"
import { Code } from "@opencode-ai/ui/code"
import { ThemeProvider } from "@opencode-ai/ui/theme"
import { GlobalSyncProvider } from "@/context/global-sync"
import { PermissionProvider } from "@/context/permission"
import { LayoutProvider } from "@/context/layout"
import { GlobalSDKProvider } from "@/context/global-sdk"
import { normalizeServerUrl, ServerProvider, useServer } from "@/context/server"
import { SettingsProvider } from "@/context/settings"
import { TerminalProvider } from "@/context/terminal"
import { PromptProvider } from "@/context/prompt"
import { FileProvider } from "@/context/file"
import { CommentsProvider } from "@/context/comments"
import { NotificationProvider } from "@/context/notification"
import { ModelsProvider } from "@/context/models"
import { DialogProvider } from "@opencode-ai/ui/context/dialog"
import { CommandProvider } from "@/context/command"
import { LanguageProvider, useLanguage } from "@/context/language"
import { usePlatform } from "@/context/platform"
import { HighlightsProvider } from "@/context/highlights"
import Layout from "@/pages/layout"
import DirectoryLayout from "@/pages/directory-layout"
import { ErrorPage } from "./pages/error"
const Home = lazy(() => import("@/pages/home"))
const Session = lazy(() => import("@/pages/session"))
const Pods = lazy(() => import("@/pages/pods"))
const Agent = lazy(() => import("@/pages/agent"))
const Loading = () => <div class="size-full" />

const HomeRoute = () => (
  <Suspense fallback={<Loading />}>
    <Home />
  </Suspense>
)

const SessionRoute = () => (
  <SessionProviders>
    <Suspense fallback={<Loading />}>
      <Session />
    </Suspense>
  </SessionProviders>
)

const SessionIndexRoute = () => <Navigate href="session" />

function UiI18nBridge(props: ParentProps) {
  const language = useLanguage()
  return <I18nProvider value={{ locale: language.locale, t: language.t }}>{props.children}</I18nProvider>
}

declare global {
  interface Window {
    __OPENCODE__?: { updaterEnabled?: boolean; serverPassword?: string; deepLinks?: string[]; wsl?: boolean }
  }
}

function MarkedProviderWithNativeParser(props: ParentProps) {
  const platform = usePlatform()
  return <MarkedProvider nativeParser={platform.parseMarkdown}>{props.children}</MarkedProvider>
}

function AppShellProviders(props: ParentProps) {
  return (
    <SettingsProvider>
      <PermissionProvider>
        <LayoutProvider>
          <NotificationProvider>
            <ModelsProvider>
              <CommandProvider>
                <HighlightsProvider>
                  <Layout>{props.children}</Layout>
                </HighlightsProvider>
              </CommandProvider>
            </ModelsProvider>
          </NotificationProvider>
        </LayoutProvider>
      </PermissionProvider>
    </SettingsProvider>
  )
}

function SessionProviders(props: ParentProps) {
  return (
    <TerminalProvider>
      <FileProvider>
        <PromptProvider>
          <CommentsProvider>{props.children}</CommentsProvider>
        </PromptProvider>
      </FileProvider>
    </TerminalProvider>
  )
}

/** Layout route for the opencode session UI — wraps children in the full provider stack. */
function OpenCodeLayout(props: ParentProps<{ appChildren?: JSX.Element }>) {
  return (
    <AppShellProviders>
      {props.appChildren}
      {props.children}
    </AppShellProviders>
  )
}

const getStoredDefaultServerUrl = (platform: ReturnType<typeof usePlatform>) => {
  if (platform.platform !== "web") return
  const result = platform.getDefaultServerUrl?.()
  if (result instanceof Promise) return
  if (!result) return
  return normalizeServerUrl(result)
}

const resolveDefaultServerUrl = (props: {
  defaultUrl?: string
  storedDefaultServerUrl?: string
  hostname: string
  origin: string
  isDev: boolean
  devHost?: string
  devPort?: string
}) => {
  if (props.defaultUrl) return props.defaultUrl
  if (props.storedDefaultServerUrl) return props.storedDefaultServerUrl
  if (props.hostname.includes("opencode.ai")) return "http://localhost:4096"
  if (props.isDev) return `http://${props.devHost ?? "localhost"}:${props.devPort ?? "4096"}`
  return props.origin
}

export function AppBaseProviders(props: ParentProps) {
  return (
    <MetaProvider>
      <Font />
      <ThemeProvider>
        <LanguageProvider>
          <UiI18nBridge>
            <ErrorBoundary fallback={(error) => <ErrorPage error={error} />}>
              <DialogProvider>
                <MarkedProviderWithNativeParser>
                  <DiffComponentProvider component={Diff}>
                    <CodeComponentProvider component={Code}>{props.children}</CodeComponentProvider>
                  </DiffComponentProvider>
                </MarkedProviderWithNativeParser>
              </DialogProvider>
            </ErrorBoundary>
          </UiI18nBridge>
        </LanguageProvider>
      </ThemeProvider>
    </MetaProvider>
  )
}

function ServerKey(props: ParentProps) {
  const server = useServer()
  if (!server.url) return null
  return props.children
}

const PodsRoute = () => (
  <Suspense fallback={<Loading />}>
    <Pods />
  </Suspense>
)

const AgentRoute = () => (
  <ErrorBoundary fallback={(err) => (
    <div class="flex items-center justify-center h-screen bg-surface-base text-text-strong">
      <div class="max-w-lg p-6 rounded-lg border border-border-base bg-fill-element-base">
        <h1 class="text-lg font-semibold mb-2">Something went wrong</h1>
        <p class="text-sm opacity-70 mb-3">An error occurred while loading the agent session.</p>
        <details class="text-xs font-mono bg-surface-inset rounded p-3 mb-4 max-h-48 overflow-y-auto">
          <summary class="cursor-pointer mb-1 font-medium">Error Details</summary>
          <pre class="whitespace-pre-wrap break-all">{err?.message ?? String(err)}</pre>
          <Show when={err?.stack}>
            <pre class="whitespace-pre-wrap break-all mt-2 opacity-50">{err.stack}</pre>
          </Show>
        </details>
        <button
          type="button"
          class="px-4 py-2 rounded text-sm font-medium bg-blue-900 border border-blue-700 text-blue-300 hover:bg-blue-800 cursor-pointer"
          onClick={() => window.location.reload()}
        >
          Reload Page
        </button>
      </div>
    </div>
  )}>
    <Suspense fallback={<Loading />}>
      <Agent />
    </Suspense>
  </ErrorBoundary>
)

export function AppInterface(props: { defaultUrl?: string; children?: JSX.Element; isSidecar?: boolean }) {
  const platform = usePlatform()
  const storedDefaultServerUrl = getStoredDefaultServerUrl(platform)
  const defaultServerUrl = resolveDefaultServerUrl({
    defaultUrl: props.defaultUrl,
    storedDefaultServerUrl,
    hostname: location.hostname,
    origin: window.location.origin,
    isDev: import.meta.env.DEV,
    devHost: import.meta.env.VITE_OPENCODE_SERVER_HOST,
    devPort: import.meta.env.VITE_OPENCODE_SERVER_PORT,
  })

  return (
    <Router>
      {/* /pods and /agent/:name — standalone pages, no opencode server needed */}
      <Route path="/pods" component={PodsRoute} />
      <Route path="/agent/:name" component={AgentRoute} />

      {/* Everything else goes through the full opencode provider stack */}
      <Route
        path=""
        component={(routerProps) => (
          <ServerProvider defaultUrl={defaultServerUrl} isSidecar={props.isSidecar}>
            <ServerKey>
              <GlobalSDKProvider>
                <GlobalSyncProvider>
                  <OpenCodeLayout appChildren={props.children}>{routerProps.children}</OpenCodeLayout>
                </GlobalSyncProvider>
              </GlobalSDKProvider>
            </ServerKey>
          </ServerProvider>
        )}
      >
        <Route path="/" component={HomeRoute} />
        <Route path="/:dir" component={DirectoryLayout}>
          <Route path="/" component={SessionIndexRoute} />
          <Route path="/session/:id?" component={SessionRoute} />
        </Route>
      </Route>
    </Router>
  )
}

import { Component, createMemo, createSignal, onMount, Show } from "solid-js"
import { Dialog } from "@opencode-ai/ui/dialog"
import { Switch } from "@opencode-ai/ui/switch"
import { Icon } from "@opencode-ai/ui/icon"
import { Spinner } from "@opencode-ai/ui/spinner"
import { devaipodAdminToken } from "@/utils/persist"

/** GitHub repo permission flags */
interface GhRepoPermission {
  read?: boolean
  "create-draft"?: boolean
  "pending-review"?: boolean
  "push-new-branch"?: boolean
  write?: boolean
}

interface GhScope {
  read?: boolean
  repos?: Record<string, GhRepoPermission>
}

interface GatorScopeConfig {
  gh?: GhScope
}

interface GatorScopesResponse {
  enabled: boolean
  scopes?: GatorScopeConfig
}

export const DialogGator: Component = () => {
  const [loading, setLoading] = createSignal(true)
  const [saving, setSaving] = createSignal(false)
  const [error, setError] = createSignal("")
  const [gatorState, setGatorState] = createSignal<GatorScopesResponse | null>(null)
  const [adminToken, setAdminToken] = createSignal("")

  onMount(async () => {
    try {
      setAdminToken(devaipodAdminToken() ?? "")
      const scopesResp = await fetch("/gator/scopes").then((r) => r.json())
      setGatorState(scopesResp)
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setLoading(false)
    }
  })

  const targetRepo = createMemo(() => {
    const scopes = gatorState()?.scopes
    if (!scopes?.gh?.repos) return null
    const repos = Object.keys(scopes.gh.repos)
    return repos.find((r) => !r.includes("*")) ?? repos[0] ?? null
  })

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

  async function togglePermission(permission: "draft-pr" | "draft-review", enabled: boolean) {
    const state = gatorState()
    if (!state?.scopes) return

    setSaving(true)
    setError("")

    try {
      const newScopes: GatorScopeConfig = JSON.parse(JSON.stringify(state.scopes))
      if (!newScopes.gh) newScopes.gh = {}
      if (!newScopes.gh.repos) newScopes.gh.repos = {}

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

      const resp = await fetch("/gator/scopes", {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${adminToken()}`,
        },
        body: JSON.stringify({ scopes: newScopes }),
      })

      if (!resp.ok) {
        throw new Error(`Failed to update: ${resp.status}`)
      }

      const result: GatorScopesResponse = await resp.json()
      setGatorState(result)
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setSaving(false)
    }
  }

  return (
    <Dialog size="medium" transition>
      <div class="flex flex-col gap-4 p-6">
        <div class="flex items-center gap-3">
          <Icon name="sliders" size="base" class="text-text-secondary-base" />
          <div>
            <h2 class="text-base font-medium text-text-primary-base">Service Gator</h2>
            <p class="text-12-regular text-text-secondary-base">Control GitHub permissions for this workspace</p>
          </div>
        </div>

        <Show when={loading()}>
          <div class="flex items-center gap-2 text-12-regular text-text-secondary-base py-4">
            <Spinner class="size-4" />
            Loading permissions...
          </div>
        </Show>

        <Show when={!loading() && !gatorState()?.enabled}>
          <p class="text-12-regular text-text-secondary-base py-4">
            Service-gator is not enabled for this workspace.
          </p>
        </Show>

        <Show when={!loading() && gatorState()?.enabled}>
          <Show
            when={targetRepo()}
            fallback={
              <p class="text-12-regular text-text-secondary-base py-4">
                Read-only access enabled. No repository scopes configured for write control.
              </p>
            }
          >
            <div class="flex flex-col gap-1 pb-2">
              <span class="text-11-regular text-text-secondary-base">Repository</span>
              <span class="text-13-medium font-mono text-text-primary-base">{targetRepo()}</span>
            </div>

            <div class="flex flex-col gap-4 border-t border-border-base pt-4">
              <div class="flex items-center justify-between">
                <div class="flex flex-col gap-0.5">
                  <span class="text-13-medium text-text-primary-base">Draft PRs</span>
                  <span class="text-12-regular text-text-secondary-base">
                    Create draft pull requests and push branches
                  </span>
                </div>
                <Switch checked={hasDraftPr()} disabled={saving()} onChange={(c) => togglePermission("draft-pr", c)} />
              </div>

              <div class="flex items-center justify-between">
                <div class="flex flex-col gap-0.5">
                  <span class="text-13-medium text-text-primary-base">Draft Reviews</span>
                  <span class="text-12-regular text-text-secondary-base">Create pending PR reviews with comments</span>
                </div>
                <Switch
                  checked={hasDraftReview()}
                  disabled={saving()}
                  onChange={(c) => togglePermission("draft-review", c)}
                />
              </div>
            </div>

            <Show when={saving()}>
              <div class="flex items-center gap-2 text-12-regular text-text-secondary-base">
                <Spinner class="size-3.5" />
                Updating...
              </div>
            </Show>
          </Show>
        </Show>

        <Show when={error()}>
          <div class="rounded-md bg-fill-error-base/10 border border-border-error-base p-3">
            <span class="text-12-regular text-text-error-base">{error()}</span>
          </div>
        </Show>
      </div>
    </Dialog>
  )
}

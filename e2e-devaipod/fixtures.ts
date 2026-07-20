// Playwright fixtures for devaipod e2e tests.
//
// Provides authenticated page navigation and pod list access.
// Reads DEVAIPOD_BASE_URL and DEVAIPOD_TOKEN from env vars
// (set by global-setup.ts) and the state file for pod names.

import { test as base, expect, type Page } from "@playwright/test"
import { readFileSync } from "fs"
import { join } from "path"
import { tmpdir } from "os"

const STATE_FILE = join(tmpdir(), "devaipod-e2e-state.json")

interface State {
  pid: number
  port: number
  token: string
  baseUrl: string
  pods: string[]
}

function readState(): State {
  return JSON.parse(readFileSync(STATE_FILE, "utf-8"))
}

interface DevaipodFixtures {
  /** Base URL of the devaipod control plane */
  devaipodUrl: string
  /** Auth token */
  devaipodToken: string
  /** Full pod names created by global setup (e.g. ["devaipod-e2e-switcher-pod-a-...", ...]) */
  podNames: string[]
  /** Short pod names (without "devaipod-" prefix) */
  podShortNames: string[]
  /** Log in by navigating to the login endpoint (sets cookie) */
  login: () => Promise<void>
  /** Navigate to a pod's agent iframe (logs in first) */
  gotoAgent: (podShortName: string) => Promise<void>
  /** Navigate to a pod's SPA agent page at /agent/:name (logs in first) */
  gotoAgentSpa: (podShortName: string) => Promise<void>
}

export const test = base.extend<DevaipodFixtures>({
  devaipodUrl: async ({}, use) => {
    const state = readState()
    await use(state.baseUrl)
  },

  devaipodToken: async ({}, use) => {
    const state = readState()
    await use(state.token)
  },

  podNames: async ({}, use) => {
    const state = readState()
    await use(state.pods)
  },

  podShortNames: async ({ podNames }, use) => {
    await use(podNames.map((n) => n.replace(/^devaipod-/, "")))
  },

  login: async ({ page, devaipodUrl, devaipodToken }, use) => {
    await use(async () => {
      await page.goto(`${devaipodUrl}/_devaipod/login?token=${devaipodToken}`)
      // Login sets cookie and redirects to /pods
    })
  },

  gotoAgent: async ({ page, devaipodUrl, devaipodToken }, use) => {
    await use(async (podShortName: string) => {
      // Capture JS errors and network activity from the start
      const jsErrors: string[] = []
      const networkLog: string[] = []
      page.on("pageerror", (err) => jsErrors.push(err.message))
      page.on("console", (msg) => {
        if (msg.type() === "error") jsErrors.push(`console.error: ${msg.text()}`)
      })
      page.on("response", (r) => networkLog.push(`${r.status()} ${r.url()}`))
      page.on("requestfailed", (r) => networkLog.push(`FAILED ${r.url()} ${r.failure()?.errorText}`))

      // Login: set cookie via login endpoint AND pass token as query param
      await page.goto(`${devaipodUrl}/_devaipod/login?token=${devaipodToken}`)
      // Navigate to SPA agent page with token in query string
      await page.goto(`${devaipodUrl}/agent/${podShortName}?token=${devaipodToken}`)
      // Wait for the top bar to render (SPA renders it reactively)

      try {
        await page.waitForSelector('[data-testid="agent-topbar"]', { timeout: 30_000 })
      } catch (e) {
        const url = page.url()
        const title = await page.title()
        const rootHtml = await page.evaluate(() => {
          const root = document.getElementById("root")
          return root?.innerHTML?.substring(0, 2000) || "no #root content"
        })
        const bodyHtml = await page.evaluate(() => document.body?.innerHTML?.substring(0, 2000) || "no body")
        console.error(`gotoAgent failed for ${podShortName}:`)
        console.error(`  URL: ${url}`)
        console.error(`  Title: ${title}`)
        console.error(`  #root innerHTML: ${rootHtml}`)
        console.error(`  body innerHTML: ${bodyHtml}`)
        console.error(`  JS errors (${jsErrors.length}): ${jsErrors.join("\n    ")}`)
        console.error(`  Network log (${networkLog.length}):`)
        for (const entry of networkLog) {
          console.error(`    ${entry}`)
        }
        throw e
      }
    })
  },

  gotoAgentSpa: async ({ page, devaipodUrl, devaipodToken }, use) => {
    await use(async (podShortName: string) => {
      // Capture JS errors and network activity from the start,
      // before any navigation, so nothing is missed during page load.
      const jsErrors: string[] = []
      const networkLog: string[] = []
      page.on("pageerror", (err) => jsErrors.push(err.message))
      page.on("console", (msg) => {
        if (msg.type() === "error") jsErrors.push(`console.error: ${msg.text()}`)
      })
      page.on("response", (r) => networkLog.push(`${r.status()} ${r.url()}`))
      page.on("requestfailed", (r) => networkLog.push(`FAILED ${r.url()} ${r.failure()?.errorText}`))

      // Login: set cookie via login endpoint AND pass token as query param
      // so the SPA can store it in sessionStorage for apiFetch() calls.
      await page.goto(`${devaipodUrl}/_devaipod/login?token=${devaipodToken}`)
      // Navigate to SPA agent page with token in query string
      await page.goto(`${devaipodUrl}/agent/${podShortName}?token=${devaipodToken}`)
      // Wait for the top bar to render (SPA renders it reactively)

      try {
        await page.waitForSelector('[data-testid="agent-topbar"]', { timeout: 30_000 })
      } catch (e) {
        const url = page.url()
        const title = await page.title()
        const rootHtml = await page.evaluate(() => {
          const root = document.getElementById("root")
          return root?.innerHTML?.substring(0, 2000) || "no #root content"
        })
        const bodyHtml = await page.evaluate(() => document.body?.innerHTML?.substring(0, 2000) || "no body")
        console.error(`gotoAgentSpa failed for ${podShortName}:`)
        console.error(`  URL: ${url}`)
        console.error(`  Title: ${title}`)
        console.error(`  #root innerHTML: ${rootHtml}`)
        console.error(`  body innerHTML: ${bodyHtml}`)
        console.error(`  JS errors (${jsErrors.length}): ${jsErrors.join("\n    ")}`)
        console.error(`  Network log (${networkLog.length}):`)
        for (const entry of networkLog) {
          console.error(`    ${entry}`)
        }
        throw e
      }
    })
  },
})

export { expect }

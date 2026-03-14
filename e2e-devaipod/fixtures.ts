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
      // Login to set auth cookie
      await page.goto(`${devaipodUrl}/_devaipod/login?token=${devaipodToken}`)
      // Navigate to agent iframe
      await page.goto(`${devaipodUrl}/_devaipod/agent/${podShortName}/`)
      // Wait for the top bar to render
      await page.waitForSelector("#dbar", { timeout: 10_000 })
    })
  },
})

export { expect }

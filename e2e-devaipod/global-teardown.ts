// Global teardown: remove test pods and kill the devaipod web server.

import { execSync } from "child_process"
import { readFileSync, rmSync, existsSync } from "fs"
import { join } from "path"
import { tmpdir } from "os"

const STATE_FILE = join(tmpdir(), "devaipod-e2e-state.json")

export default async function globalTeardown() {
  console.log("[e2e-devaipod] Starting teardown...")

  if (!existsSync(STATE_FILE)) {
    console.log("[e2e-devaipod] No state file, nothing to clean up.")
    return
  }

  const state = JSON.parse(readFileSync(STATE_FILE, "utf-8"))

  // Remove pods and their volumes
  const volumeSuffixes = ["-workspace", "-agent-home", "-agent-workspace", "-worker-home", "-worker-workspace"]
  for (const pod of state.pods || []) {
    console.log(`[e2e-devaipod] Removing pod ${pod}...`)
    try {
      execSync(`podman pod rm -f ${pod}`, { timeout: 30_000 })
    } catch {}
    for (const suffix of volumeSuffixes) {
      try {
        execSync(`podman volume rm -f ${pod}${suffix}`, { timeout: 10_000 })
      } catch {}
    }
  }

  // Kill the web server
  if (state.pid) {
    console.log(`[e2e-devaipod] Killing devaipod web (pid ${state.pid})...`)
    try {
      process.kill(state.pid, "SIGTERM")
    } catch {}
  }

  // Clean up temp dirs
  for (const dir of state.tmpDirs || []) {
    try {
      rmSync(dir, { recursive: true, force: true })
    } catch {}
  }

  // Remove state file
  try {
    rmSync(STATE_FILE)
  } catch {}

  console.log("[e2e-devaipod] Teardown complete.")
}

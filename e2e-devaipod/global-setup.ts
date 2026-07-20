// Global setup: start devaipod web server, create test pods.
//
// The devaipod binary must be available in PATH (it is when running
// inside the integration-web-runner container image).
//
// Exports DEVAIPOD_BASE_URL, DEVAIPOD_TOKEN, and pod names via a
// JSON state file read by fixtures and global-teardown.

import { execSync, spawn, ChildProcess } from "child_process"
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from "fs"
import { join } from "path"
import { tmpdir } from "os"

const STATE_FILE = join(tmpdir(), "devaipod-e2e-state.json")

interface State {
  pid: number
  port: number
  token: string
  baseUrl: string
  pods: string[]
  tmpDirs: string[]
}

function findFreePort(): number {
  // Use node's net module to find a free port
  const net = require("net")
  const srv = net.createServer()
  srv.listen(0)
  const port = srv.address().port
  srv.close()
  return port
}

function createTestRepo(name: string): string {
  // Use /tmp explicitly (not tmpdir() which returns /var/folders/... on macOS).
  // The Justfile mounts -v /tmp:/tmp:shared so /tmp is visible to both the
  // test container and sibling containers spawned by devaipod.
  const dir = mkdtempSync(join("/tmp", `devaipod-e2e-${name}-`))
  const repo = join(dir, "repo")
  mkdirSync(repo)
  execSync("git init", { cwd: repo })
  execSync('git config user.email "test@example.com"', { cwd: repo })
  execSync('git config user.name "Test"', { cwd: repo })

  // devcontainer.json (required by devaipod)
  const dcDir = join(repo, ".devcontainer")
  mkdirSync(dcDir)
  const image = process.env.DEVAIPOD_TEST_IMAGE || "ghcr.io/bootc-dev/devenv-debian:latest"
  writeFileSync(
    join(dcDir, "devcontainer.json"),
    JSON.stringify({ name, image }, null, 2),
  )
  writeFileSync(join(repo, "README.md"), `# ${name}\n`)
  execSync("git remote add origin https://github.com/test/e2e-test.git", { cwd: repo })
  execSync("git add .", { cwd: repo })
  execSync('git commit -m "Initial commit"', { cwd: repo })
  return repo
}

function waitForToken(proc: ChildProcess, timeoutMs: number): Promise<{ token: string }> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("Timeout waiting for token")), timeoutMs)
    let buffer = ""

    const onData = (chunk: Buffer) => {
      buffer += chunk.toString()
      for (const line of buffer.split("\n")) {
        const idx = line.indexOf("token=")
        if (idx >= 0) {
          let token = line.substring(idx + 6).trim()
          // Token ends at whitespace/quote/end
          const end = token.search(/[\s"']/)
          if (end >= 0) token = token.substring(0, end)
          if (token) {
            clearTimeout(timer)
            resolve({ token })
            return
          }
        }
      }
    }

    proc.stdout?.on("data", onData)
    proc.stderr?.on("data", onData)
    proc.on("exit", (code) => {
      clearTimeout(timer)
      reject(new Error(`devaipod exited with code ${code} before printing token`))
    })
  })
}

function waitForHealth(baseUrl: string, timeoutMs: number): Promise<void> {
  return new Promise((resolve, reject) => {
    const start = Date.now()
    const poll = async () => {
      try {
        const resp = await fetch(`${baseUrl}/_devaipod/health`)
        if (resp.ok) {
          resolve()
          return
        }
      } catch {}
      if (Date.now() - start > timeoutMs) {
        reject(new Error("Health endpoint timeout"))
        return
      }
      setTimeout(poll, 200)
    }
    poll()
  })
}

function waitForPodRunning(baseUrl: string, token: string, podName: string, timeoutMs: number): Promise<void> {
  return new Promise((resolve, reject) => {
    const start = Date.now()
    const poll = async () => {
      try {
        const resp = await fetch(`${baseUrl}/api/devaipod/pods`, {
          headers: { Authorization: `Bearer ${token}` },
        })
        if (resp.ok) {
          const pods: any[] = await resp.json()
          const pod = pods.find((p) => p.name === podName)
          if (pod && pod.status.toLowerCase() === "running") {
            resolve()
            return
          }
        }
      } catch {}
      if (Date.now() - start > timeoutMs) {
        reject(new Error(`Pod ${podName} did not become Running within ${timeoutMs}ms`))
        return
      }
      setTimeout(poll, 2000)
    }
    poll()
  })
}

function waitForApiHealthy(podName: string, timeoutMs: number): Promise<void> {
  return new Promise((resolve, reject) => {
    const start = Date.now()
    const apiContainer = `${podName}-api`
    const poll = () => {
      try {
        const out = execSync(
          `podman inspect --format "{{.State.Health.Status}}" ${apiContainer}`,
          { encoding: "utf-8", timeout: 5000 },
        ).trim()
        if (out === "healthy") {
          resolve()
          return
        }
      } catch {}
      if (Date.now() - start > timeoutMs) {
        reject(new Error(`${apiContainer} did not become healthy within ${timeoutMs}ms`))
        return
      }
      setTimeout(poll, 1000)
    }
    poll()
  })
}

export default async function globalSetup() {
  console.log("[e2e-devaipod] Starting global setup...")

  const port = findFreePort()
  const baseUrl = `http://127.0.0.1:${port}`
  const tmpDirs: string[] = []

  // Workspace directory must be under /tmp (shared with sibling containers
  // via the Justfile's -v /tmp:/tmp:shared mount).
  const workspacesDir = mkdtempSync(join("/tmp", "devaipod-e2e-workspaces-"))
  tmpDirs.push(workspacesDir)

  // Start devaipod web server
  const proc = spawn("devaipod-server", ["web", "--port", String(port)], {
    env: {
      ...process.env,
      DEVAIPOD_INSTANCE: "integration-test",
      DEVAIPOD_HOST_MODE: "1",
      DEVAIPOD_MOCK_AGENT: "1",
      DEVAIPOD_HOST_WORKDIR: workspacesDir,
    },
    stdio: ["ignore", "pipe", "pipe"],
  })

  const { token } = await waitForToken(proc, 30_000)
  console.log(`[e2e-devaipod] Got token, waiting for health on port ${port}...`)
  await waitForHealth(baseUrl, 30_000)
  console.log("[e2e-devaipod] Server healthy.")

  // Create two test pods
  const pods: string[] = []
  for (const suffix of ["pod-a", "pod-b"]) {
    const repoPath = createTestRepo(suffix)
    tmpDirs.push(repoPath)
    const shortName = `e2e-switcher-${suffix}-${Date.now()}`
    const fullName = `devaipod-${shortName}`

    console.log(`[e2e-devaipod] Creating pod ${shortName}...`)
    const body = JSON.stringify({ source: repoPath, name: shortName })
    const resp = await fetch(`${baseUrl}/api/devaipod/run`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body,
    })
    if (!resp.ok) {
      const text = await resp.text()
      throw new Error(`Failed to create pod ${shortName}: ${resp.status} ${text}`)
    }

    console.log(`[e2e-devaipod] Waiting for ${fullName} to be Running...`)
    await waitForPodRunning(baseUrl, token, fullName, 120_000)

    console.log(`[e2e-devaipod] Waiting for ${fullName}-api to be healthy...`)
    await waitForApiHealthy(fullName, 60_000)

    pods.push(fullName)
    console.log(`[e2e-devaipod] Pod ${fullName} is ready.`)
  }

  // Write state for fixtures and teardown
  const state: State = { pid: proc.pid!, port, token, baseUrl, pods, tmpDirs }
  writeFileSync(STATE_FILE, JSON.stringify(state))

  // Set env vars for Playwright config
  process.env.DEVAIPOD_BASE_URL = baseUrl
  process.env.DEVAIPOD_TOKEN = token

  console.log(`[e2e-devaipod] Setup complete. ${pods.length} pods ready.`)
}

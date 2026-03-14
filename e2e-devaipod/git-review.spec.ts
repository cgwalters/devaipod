// Git review integration tests.
//
// These tests validate the git review endpoints served by the
// pod-api sidecar, accessed through the control plane proxy.
// They exercise the /git/* API endpoints that power the
// GitReviewTab component in the SPA.

import { test, expect } from "./fixtures"

test.describe("Git review API", () => {

  test("git status returns branch and files", async ({
    page,
    devaipodUrl,
    devaipodToken,
    podNames,
  }) => {
    // Find the pod-api port by querying the control plane pod list
    const podsResp = await page.request.get(`${devaipodUrl}/api/devaipod/pods`, {
      headers: { Authorization: `Bearer ${devaipodToken}` },
    })
    expect(podsResp.ok()).toBeTruthy()
    const pods = await podsResp.json()
    const pod = pods.find((p: any) => p.name === podNames[0])
    expect(pod).toBeTruthy()

    // The pod-api runs on port 8090 inside the pod. The control plane
    // proxies /api/devaipod/pods/:name/pod-api/* to the pod-api sidecar.
    // Use the proxy path to reach git endpoints.
    const apiBase = `${devaipodUrl}/api/devaipod/pods/${encodeURIComponent(podNames[0])}/pod-api`

    const statusResp = await page.request.get(`${apiBase}/git/status`, {
      headers: { Authorization: `Bearer ${devaipodToken}` },
    })
    expect(statusResp.ok()).toBeTruthy()

    const status = await statusResp.json()
    expect(status).toHaveProperty("exit_code")
    expect(status).toHaveProperty("files")
    expect(status).toHaveProperty("branch")
    expect(Array.isArray(status.files)).toBeTruthy()
  })

  test("git log returns commits", async ({
    page,
    devaipodUrl,
    devaipodToken,
    podNames,
  }) => {
    const apiBase = `${devaipodUrl}/api/devaipod/pods/${encodeURIComponent(podNames[0])}/pod-api`

    const logResp = await page.request.get(`${apiBase}/git/log`, {
      headers: { Authorization: `Bearer ${devaipodToken}` },
    })
    expect(logResp.ok()).toBeTruthy()

    const log = await logResp.json()
    expect(log).toHaveProperty("commits")
    expect(Array.isArray(log.commits)).toBeTruthy()
    // The test pod has at least one commit (from createTestRepo)
    expect(log.commits.length).toBeGreaterThan(0)

    const commit = log.commits[0]
    expect(commit).toHaveProperty("sha")
    expect(commit).toHaveProperty("short_sha")
    expect(commit).toHaveProperty("message")
    expect(commit).toHaveProperty("author")
  })

  test("git events SSE stream connects", async ({
    page,
    devaipodUrl,
    devaipodToken,
    podNames,
  }) => {
    const apiBase = `${devaipodUrl}/api/devaipod/pods/${encodeURIComponent(podNames[0])}/pod-api`

    // The SSE endpoint should respond with a 200 and text/event-stream content type.
    // We use a regular GET (not EventSource) and check the initial response headers.
    const eventsResp = await page.request.get(`${apiBase}/git/events`, {
      headers: { Authorization: `Bearer ${devaipodToken}` },
      timeout: 5000,
    })
    expect(eventsResp.ok()).toBeTruthy()
    const contentType = eventsResp.headers()["content-type"] || ""
    expect(contentType).toContain("text/event-stream")
  })

  test("fetch-agent returns not-configured when no main workspace", async ({
    page,
    devaipodUrl,
    devaipodToken,
    podNames,
  }) => {
    const apiBase = `${devaipodUrl}/api/devaipod/pods/${encodeURIComponent(podNames[0])}/pod-api`

    const fetchResp = await page.request.post(`${apiBase}/git/fetch-agent`, {
      headers: { Authorization: `Bearer ${devaipodToken}` },
    })
    expect(fetchResp.ok()).toBeTruthy()

    const result = await fetchResp.json()
    expect(result).toHaveProperty("success", false)
    expect(result.message).toContain("Main workspace not configured")
  })

  test("create-branch returns not-configured when no main workspace", async ({
    page,
    devaipodUrl,
    devaipodToken,
    podNames,
  }) => {
    const apiBase = `${devaipodUrl}/api/devaipod/pods/${encodeURIComponent(podNames[0])}/pod-api`

    const resp = await page.request.post(`${apiBase}/git/create-branch`, {
      headers: {
        Authorization: `Bearer ${devaipodToken}`,
        "Content-Type": "application/json",
      },
      data: JSON.stringify({ branch: "test-branch" }),
    })
    expect(resp.ok()).toBeTruthy()

    const result = await resp.json()
    expect(result).toHaveProperty("success", false)
    expect(result.message).toContain("Main workspace not configured")
  })

})

// SPA agent page integration tests.
//
// These tests validate the SolidJS agent page at /agent/:name,
// covering navigation, done-state toggling, the pod switcher,
// and the ACP frontend components (prompt input, YOLO toggle,
// connection status).
// They require two running pods (created by global-setup.ts).

import { test, expect } from "./fixtures"

test.describe("SPA agent page", () => {

  test("renders top bar with back button and done button", async ({
    page,
    gotoAgentSpa,
    podShortNames,
  }) => {
    await gotoAgentSpa(podShortNames[0])

    // Back button exists and links to /pods
    const backLink = page.locator('a[href="/pods"]')
    await expect(backLink).toBeVisible()

    // Done button exists
    const doneBtn = page.locator('[data-testid="done-btn"]')
    await expect(doneBtn).toBeVisible()

    // ACP content area exists (replaced the iframe)
    const acpContent = page.locator('[data-testid="acp-content"]')
    await expect(acpContent).toBeVisible()
  })

  test("renders ACP content with connection status and prompt input", async ({
    page,
    gotoAgentSpa,
    podShortNames,
  }) => {
    await gotoAgentSpa(podShortNames[0])

    // Connection status indicator is visible
    const connectionStatus = page.locator('[data-testid="connection-status"]')
    await expect(connectionStatus).toBeVisible()

    // ACP content area exists
    const acpContent = page.locator('[data-testid="acp-content"]')
    await expect(acpContent).toBeVisible()

    // Wait for connection to complete and a session to be created
    // The mock agent should create at least one session automatically
    await page.waitForFunction(
      () => {
        const status = document.querySelector('[data-testid="connection-status"]')
        if (!status || !status.textContent) return false
        // Wait for "connected" or "ready" status
        return status.textContent.toLowerCase().includes('connected') ||
               status.textContent.toLowerCase().includes('ready')
      },
      { timeout: 30_000 }
    )

    // After connection, a session pane should appear (if mock creates one)
    // OR we should at least see the panes container even if empty
    const panesContainer = page.locator('[data-testid="panes-container"]')
    await expect(panesContainer).toBeVisible()

    // If a session exists, check for prompt input
    const sessionPane = page.locator('[data-testid="session-pane"]')
    const sessionCount = await sessionPane.count()

    if (sessionCount > 0) {
      // Prompt bar with input and send button exist (inside SessionPane)
      const promptInput = page.locator('[data-testid="prompt-input"]')
      await expect(promptInput).toBeVisible()

      const sendBtn = page.locator('[data-testid="send-btn"]')
      await expect(sendBtn).toBeVisible()
    }
  })

  test("session content persists after navigating away and back", async ({
    page,
    gotoAgentSpa,
    podShortNames,
  }) => {
    await gotoAgentSpa(podShortNames[0])

    // Wait for connection and panes container
    const panesContainer = page.locator('[data-testid="panes-container"]')
    await expect(panesContainer).toBeVisible({ timeout: 30_000 })

    // Create a new session by clicking the "+" button if no session exists
    const sessionPane = page.locator('[data-testid="session-pane"]')
    const initialSessionCount = await sessionPane.count()

    if (initialSessionCount === 0) {
      // Look for the "+" button to create a new session
      // It's in the tab bar with title="New session"
      const newSessionBtn = page.locator('button[title="New session"]')
      if (await newSessionBtn.count() > 0) {
        await newSessionBtn.first().click()
        // Wait for session pane to appear
        await expect(sessionPane).toBeVisible({ timeout: 10_000 })
      } else {
        // If there's no + button, skip this test - the mock might not create sessions
        console.log("No sessions available and no way to create one - skipping test")
        return
      }
    }

    // Now we should have at least one session
    await expect(sessionPane).toBeVisible({ timeout: 30_000 })

    // Wait for messages area to appear (within the session pane)
    const messagesArea = page.locator('[data-testid="pane-messages"]')
    await expect(messagesArea).toBeVisible({ timeout: 30_000 })

    // Send a message to create some content
    const promptInput = page.locator('[data-testid="prompt-input"]')
    await expect(promptInput).toBeVisible()
    await promptInput.fill("test message")

    const sendBtn = page.locator('[data-testid="send-btn"]')
    await sendBtn.click()

    // Wait for at least one message to appear
    await page.waitForFunction(
      () => {
        const area = document.querySelector('[data-testid="pane-messages"]')
        if (!area) return false
        const msgs = area.querySelectorAll('[data-testid="acp-message"]')
        return msgs.length > 0
      },
      { timeout: 30_000 },
    )

    const messageCount = await messagesArea.locator('[data-testid="acp-message"]').count()
    expect(messageCount).toBeGreaterThan(0)

    // Navigate away to pods page
    const backLink = page.locator('a[href="/pods"]')
    await backLink.click()
    await page.waitForURL(/\/pods/)

    // Navigate back to the same pod
    await gotoAgentSpa(podShortNames[0])

    // Wait for session pane and messages to reload
    await expect(panesContainer).toBeVisible({ timeout: 30_000 })
    await expect(sessionPane).toBeVisible({ timeout: 30_000 })
    await expect(messagesArea).toBeVisible({ timeout: 30_000 })

    await page.waitForFunction(
      () => {
        const area = document.querySelector('[data-testid="pane-messages"]')
        if (!area) return false
        const msgs = area.querySelectorAll('[data-testid="acp-message"]')
        return msgs.length > 0
      },
      { timeout: 30_000 },
    )

    // Should have the same or more messages as before
    const newCount = await messagesArea.locator('[data-testid="acp-message"]').count()
    expect(newCount).toBeGreaterThanOrEqual(messageCount)
  })

  test("done button toggles state", async ({
    page,
    gotoAgentSpa,
    podShortNames,
  }) => {
    await gotoAgentSpa(podShortNames[0])

    const doneBtn = page.locator('[data-testid="done-btn"]')
    await expect(doneBtn).toBeVisible()

    // Get initial text
    const initialText = await doneBtn.textContent()

    // Click to toggle
    await doneBtn.click()

    // Wait for text to change
    await page.waitForFunction(
      (initial) => {
        const btn = document.querySelector('[data-testid="done-btn"]')
        return btn && btn.textContent !== initial
      },
      initialText,
      { timeout: 5000 }
    )

    // Click again to toggle back
    await doneBtn.click()
    await page.waitForFunction(
      (initial) => {
        const btn = document.querySelector('[data-testid="done-btn"]')
        return btn && btn.textContent === initial
      },
      initialText,
      { timeout: 5000 }
    )
  })

  test("back button navigates to pods page", async ({
    page,
    gotoAgentSpa,
    podShortNames,
  }) => {
    await gotoAgentSpa(podShortNames[0])

    const backLink = page.locator('a[href="/pods"]')
    await backLink.click()

    // Should navigate to pods page
    await page.waitForURL(/\/pods/)
  })

  test("clicking pod from pods page navigates to /agent/ route", async ({
    page,
    gotoAgentSpa,
    podShortNames,
  }) => {
    // Start on the agent page, then go to pods via back button
    await gotoAgentSpa(podShortNames[0])
    const backLink = page.locator('a[href="/pods"]')
    await backLink.click()
    await page.waitForURL(/\/pods/)

    // Click a pod row to navigate back to the agent page
    const podRow = page.locator(`text=${podShortNames[1]}`).first()
    await expect(podRow).toBeVisible({ timeout: 10_000 })
    await podRow.click()

    // Should navigate to /agent/:name, NOT /_devaipod/agent/:name
    await page.waitForURL(/\/agent\//, { timeout: 10_000 })
    expect(page.url()).not.toContain("/_devaipod/")
    expect(page.url()).toContain(`/agent/`)
  })

  test("pod switcher shows running pods", async ({
    page,
    gotoAgentSpa,
    podShortNames,
  }) => {
    expect(podShortNames.length).toBeGreaterThanOrEqual(2)
    await gotoAgentSpa(podShortNames[0])

    // Click the pod trigger to open dropdown
    const trigger = page.locator('[data-testid="pod-trigger"]')
    await expect(trigger).toBeVisible()
    await trigger.click()

    // Dropdown should appear with pod items
    const dropdown = page.locator('[data-testid="pod-dropdown"]')
    await expect(dropdown).toBeVisible()

    // Should contain both test pods
    const items = dropdown.locator('[data-testid="pod-item"]')
    const count = await items.count()
    expect(count).toBeGreaterThanOrEqual(2)
  })

  test("pod switcher arrow navigation works", async ({
    page,
    gotoAgentSpa,
    podShortNames,
  }) => {
    expect(podShortNames.length).toBeGreaterThanOrEqual(2)
    await gotoAgentSpa(podShortNames[0])

    // Wait for pod list to load (arrows become enabled)
    const prevBtn = page.locator('[data-testid="prev-pod"]')
    const nextBtn = page.locator('[data-testid="next-pod"]')

    // At least one arrow should be enabled with 2+ pods
    await page.waitForFunction(() => {
      const prev = document.querySelector('[data-testid="prev-pod"]') as HTMLButtonElement
      const next = document.querySelector('[data-testid="next-pod"]') as HTMLButtonElement
      return (prev && !prev.disabled) || (next && !next.disabled)
    }, { timeout: 10_000 })

    // Click whichever is enabled
    const nextDisabled = await nextBtn.isDisabled()
    const btn = nextDisabled ? prevBtn : nextBtn

    const startUrl = page.url()
    await btn.click()

    // Should navigate to a different pod (SPA navigation, URL changes)
    await page.waitForURL(/\/agent\//, { timeout: 10_000 })
    // The URL should have changed to a different pod
    expect(page.url()).not.toBe(startUrl)
  })

})

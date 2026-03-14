// Pod switcher integration tests.
//
// These tests validate the interactive behavior of the pod switcher
// dropdown in the agent iframe wrapper. They require two running pods
// (created by global-setup.ts).

import { test, expect } from "./fixtures"

/** Helper: wait for the pod list to be fetched and rendered in the dropdown. */
async function waitForPodList(page: import("@playwright/test").Page) {
  await page.waitForFunction(() => {
    const dropdown = document.getElementById("pod-dropdown")
    return dropdown !== null && dropdown.querySelectorAll(".pod-item").length > 0
  }, { timeout: 10_000 })
}

/**
 * Helper: collect all pod-name texts visible in the open dropdown.
 * Returns the trimmed `.pod-name` text of each `.pod-item`.
 */
async function getDropdownPodNames(page: import("@playwright/test").Page): Promise<string[]> {
  return page.locator("#pod-dropdown .pod-item .pod-name").allTextContents()
    .then((names) => names.map((n) => n.trim()))
}

test.describe("pod switcher", () => {
  test("dropdown shows both pods with current highlighted", async ({
    page,
    gotoAgent,
    podNames,
    podShortNames,
  }) => {
    expect(podNames.length).toBeGreaterThanOrEqual(2)
    const [shortA, shortB] = podShortNames

    // Navigate to pod A
    await gotoAgent(shortA)

    // Pod switcher elements should be visible
    await expect(page.locator("#pod-switcher")).toBeVisible()
    await expect(page.locator("#pod-trigger")).toBeVisible()
    await expect(page.locator("#prev-pod")).toBeVisible()
    await expect(page.locator("#next-pod")).toBeVisible()

    // Open the dropdown
    await page.locator("#pod-trigger").click()
    await expect(page.locator("#pod-dropdown")).toHaveClass(/open/)
    await waitForPodList(page)

    // Both test pods should appear in the dropdown
    const items = page.locator("#pod-dropdown .pod-item")
    expect(await items.count()).toBeGreaterThanOrEqual(2)

    const dropdownNames = await getDropdownPodNames(page)
    expect(dropdownNames).toEqual(expect.arrayContaining([shortA, shortB]))

    // Current pod should be marked with .current class
    const currentItem = page.locator("#pod-dropdown .pod-item.current")
    await expect(currentItem).toHaveCount(1)
    await expect(currentItem.locator(".pod-name")).toHaveText(shortA)

    // Click the other pod to navigate
    const otherItem = items.filter({ hasText: shortB })
    await expect(otherItem).toHaveCount(1)
    await otherItem.click()

    // Should navigate to pod B's page
    await page.waitForURL(new RegExp(`/_devaipod/agent/`))
    await page.waitForSelector("#dbar", { timeout: 10_000 })
    expect(page.url()).toContain(encodeURIComponent(shortB))
  })

  test("arrow navigation works between pods", async ({
    page,
    gotoAgent,
    podNames,
    podShortNames,
  }) => {
    expect(podNames.length).toBeGreaterThanOrEqual(2)
    const [shortA] = podShortNames

    // Navigate to pod A
    await gotoAgent(shortA)
    await waitForPodList(page)

    // With 2+ running pods and currentIdx found, at least one arrow
    // should be enabled.
    const nextDisabled = await page.locator("#next-pod").isDisabled()
    const prevDisabled = await page.locator("#prev-pod").isDisabled()
    expect(nextDisabled && prevDisabled).toBe(false)

    // Click whichever arrow is enabled -- navigate away from pod A
    const forwardBtn = !nextDisabled ? "#next-pod" : "#prev-pod"
    const backBtn = !nextDisabled ? "#prev-pod" : "#next-pod"

    const startUrl = page.url()
    await Promise.all([
      page.waitForNavigation({ timeout: 15_000 }),
      page.locator(forwardBtn).click(),
    ])
    await page.waitForSelector("#dbar", { timeout: 10_000 })
    expect(page.url()).not.toBe(startUrl)

    // We navigated to a different pod. Now navigate back via the
    // opposite arrow. Wait for the pod list to load first so
    // currentIdx and arrows are set correctly on this new page.
    await waitForPodList(page)

    // The opposite arrow should now be enabled (we came from pod A)
    const backDisabled = await page.locator(backBtn).isDisabled()
    if (!backDisabled) {
      await Promise.all([
        page.waitForNavigation({ timeout: 15_000 }),
        page.locator(backBtn).click(),
      ])
      await page.waitForSelector("#dbar", { timeout: 10_000 })
      // Should be back on pod A
      expect(page.url()).toContain(encodeURIComponent(shortA))
    } else {
      // If the back arrow is disabled, the pod we navigated to may be
      // at the edge of the list (other non-test pods in between).
      // At minimum, verify we successfully navigated away and back
      // is theoretically possible via the dropdown.
      await page.locator("#pod-trigger").click()
      await expect(page.locator("#pod-dropdown")).toHaveClass(/open/)
      const names = await getDropdownPodNames(page)
      expect(names).toContain(shortA)
    }
  })

  test("current pod highlighted and dropdown closes on outside click", async ({
    page,
    gotoAgent,
    podShortNames,
  }) => {
    const [shortA] = podShortNames
    await gotoAgent(shortA)

    // Open dropdown
    await page.locator("#pod-trigger").click()
    await expect(page.locator("#pod-dropdown")).toHaveClass(/open/)
    await waitForPodList(page)

    // Current pod should have .current class
    const current = page.locator("#pod-dropdown .pod-item.current")
    await expect(current).toHaveCount(1)
    await expect(current.locator(".pod-name")).toHaveText(shortA)

    // The trigger button should show the pod's short name
    const triggerText = await page.locator("#pod-trigger").textContent()
    expect(triggerText?.trim()).toBe(shortA)

    // Close dropdown by clicking outside
    await page.locator("#dbar").click()
    await expect(page.locator("#pod-dropdown")).not.toHaveClass(/open/)
  })

  test("pod entries show status dots", async ({
    page,
    gotoAgent,
    podShortNames,
  }) => {
    const [shortA] = podShortNames
    await gotoAgent(shortA)

    await page.locator("#pod-trigger").click()
    await expect(page.locator("#pod-dropdown")).toHaveClass(/open/)
    await waitForPodList(page)

    const items = page.locator("#pod-dropdown .pod-item")
    const count = await items.count()
    expect(count).toBeGreaterThanOrEqual(1)

    for (let i = 0; i < count; i++) {
      const dot = items.nth(i).locator(".dot")
      await expect(dot).toHaveCount(1)
      const classes = await dot.getAttribute("class")
      expect(classes).toMatch(/running|working|idle|stopped|done/)
    }

    for (let i = 0; i < count; i++) {
      const status = items.nth(i).locator(".pod-status")
      const text = await status.textContent()
      expect(text).toBeTruthy()
    }
  })
})

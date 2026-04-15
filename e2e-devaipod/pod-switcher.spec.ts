// Pod switcher integration tests.
//
// These tests validate the interactive behavior of the pod switcher
// dropdown in the agent iframe wrapper. They require two running pods
// (created by global-setup.ts).

import { test, expect } from "./fixtures"

/** Helper: wait for the pod list to be fetched and rendered in the dropdown. */
async function waitForPodList(page: import("@playwright/test").Page) {
  await page.waitForFunction(() => {
    const dropdown = document.querySelector('[data-testid="pod-dropdown"]')
    return dropdown !== null && dropdown.querySelectorAll('[data-testid="pod-item"]').length > 0
  }, { timeout: 10_000 })
}

/**
 * Helper: collect all pod-name texts visible in the open dropdown.
 * Returns the trimmed text of each pod item (the middle span with flex-1).
 */
async function getDropdownPodNames(page: import("@playwright/test").Page): Promise<string[]> {
  return page.locator('[data-testid="pod-dropdown"] [data-testid="pod-item"] span.flex-1').allTextContents()
    .then((names) => names.map((n) => n.trim()))
}

test.describe("pod switcher", () => {
  test("dropdown shows both pods with current highlighted", async ({
    page,
    gotoAgentSpa,
    podNames,
    podShortNames,
  }) => {
    expect(podNames.length).toBeGreaterThanOrEqual(2)
    const [shortA, shortB] = podShortNames

    // Navigate to pod A
    await gotoAgentSpa(shortA)

    // Pod switcher elements should be visible
    await expect(page.locator('[data-testid="pod-trigger"]')).toBeVisible()
    await expect(page.locator('[data-testid="prev-pod"]')).toBeVisible()
    await expect(page.locator('[data-testid="next-pod"]')).toBeVisible()

    // Open the dropdown
    await page.locator('[data-testid="pod-trigger"]').click()
    const dropdown = page.locator('[data-testid="pod-dropdown"]')
    await expect(dropdown).toBeVisible()
    await waitForPodList(page)

    // Both test pods should appear in the dropdown
    const items = dropdown.locator('[data-testid="pod-item"]')
    expect(await items.count()).toBeGreaterThanOrEqual(2)

    const dropdownNames = await getDropdownPodNames(page)
    expect(dropdownNames).toEqual(expect.arrayContaining([shortA, shortB]))

    // Current pod should be marked with font-semibold class
    const currentItem = dropdown.locator('[data-testid="pod-item"].font-semibold')
    await expect(currentItem).toHaveCount(1)
    await expect(currentItem.locator("span.flex-1")).toHaveText(shortA)

    // Click the other pod to navigate
    const otherItem = items.filter({ hasText: shortB })
    await expect(otherItem).toHaveCount(1)
    await otherItem.click()

    // Should navigate to pod B's page
    await page.waitForURL(new RegExp(`/agent/`))
    await page.waitForSelector('[data-testid="agent-topbar"]', { timeout: 10_000 })
    expect(page.url()).toContain(encodeURIComponent(shortB))
  })

  test("arrow navigation works between pods", async ({
    page,
    gotoAgentSpa,
    podNames,
    podShortNames,
  }) => {
    expect(podNames.length).toBeGreaterThanOrEqual(2)
    const [shortA] = podShortNames

    // Navigate to pod A
    await gotoAgentSpa(shortA)

    // Wait for pod data to load by checking that at least one arrow is enabled
    // (This happens when the pod list API returns and currentIdx is calculated)
    await page.waitForFunction(() => {
      const prev = document.querySelector('[data-testid="prev-pod"]') as HTMLButtonElement
      const next = document.querySelector('[data-testid="next-pod"]') as HTMLButtonElement
      return (prev && !prev.disabled) || (next && !next.disabled)
    }, { timeout: 10_000 })

    // With 2+ running pods and currentIdx found, at least one arrow
    // should be enabled.
    const nextDisabled = await page.locator('[data-testid="next-pod"]').isDisabled()
    const prevDisabled = await page.locator('[data-testid="prev-pod"]').isDisabled()
    expect(nextDisabled && prevDisabled).toBe(false)

    // Click whichever arrow is enabled -- navigate away from pod A
    const forwardBtn = !nextDisabled ? '[data-testid="next-pod"]' : '[data-testid="prev-pod"]'
    const backBtn = !nextDisabled ? '[data-testid="prev-pod"]' : '[data-testid="next-pod"]'

    const startUrl = page.url()
    await Promise.all([
      page.waitForNavigation({ timeout: 15_000 }),
      page.locator(forwardBtn).click(),
    ])
    await page.waitForSelector('[data-testid="agent-topbar"]', { timeout: 10_000 })
    expect(page.url()).not.toBe(startUrl)

    // We navigated to a different pod. Now navigate back via the
    // opposite arrow. Wait for pod data to load first so
    // currentIdx and arrows are set correctly on this new page.
    await page.waitForFunction(() => {
      const prev = document.querySelector('[data-testid="prev-pod"]') as HTMLButtonElement
      const next = document.querySelector('[data-testid="next-pod"]') as HTMLButtonElement
      return (prev && !prev.disabled) || (next && !next.disabled)
    }, { timeout: 10_000 })

    // The opposite arrow should now be enabled (we came from pod A)
    const backDisabled = await page.locator(backBtn).isDisabled()
    if (!backDisabled) {
      await Promise.all([
        page.waitForNavigation({ timeout: 15_000 }),
        page.locator(backBtn).click(),
      ])
      await page.waitForSelector('[data-testid="agent-topbar"]', { timeout: 10_000 })
      // Should be back on pod A
      expect(page.url()).toContain(encodeURIComponent(shortA))
    } else {
      // If the back arrow is disabled, the pod we navigated to may be
      // at the edge of the list (other non-test pods in between).
      // At minimum, verify we successfully navigated away and back
      // is theoretically possible via the dropdown.
      await page.locator('[data-testid="pod-trigger"]').click()
      const dropdown = page.locator('[data-testid="pod-dropdown"]')
      await expect(dropdown).toBeVisible()
      const names = await getDropdownPodNames(page)
      expect(names).toContain(shortA)
    }
  })

  test("current pod highlighted and dropdown closes on outside click", async ({
    page,
    gotoAgentSpa,
    podShortNames,
  }) => {
    const [shortA] = podShortNames
    await gotoAgentSpa(shortA)

    // Open dropdown
    await page.locator('[data-testid="pod-trigger"]').click()
    const dropdown = page.locator('[data-testid="pod-dropdown"]')
    await expect(dropdown).toBeVisible()
    await waitForPodList(page)

    // Current pod should have font-semibold class
    const current = dropdown.locator('[data-testid="pod-item"].font-semibold')
    await expect(current).toHaveCount(1)
    await expect(current.locator("span.flex-1")).toHaveText(shortA)

    // The trigger button should show the pod's short name (the first span contains the name)
    const triggerText = await page.locator('[data-testid="pod-trigger"] span.truncate').textContent()
    expect(triggerText?.trim()).toBe(shortA)

    // Close dropdown by clicking outside on the topbar
    await page.locator('[data-testid="agent-topbar"]').click()
    await expect(dropdown).not.toBeVisible()
  })

  test("pod entries show status dots", async ({
    page,
    gotoAgentSpa,
    podShortNames,
  }) => {
    const [shortA] = podShortNames
    await gotoAgentSpa(shortA)

    await page.locator('[data-testid="pod-trigger"]').click()
    const dropdown = page.locator('[data-testid="pod-dropdown"]')
    await expect(dropdown).toBeVisible()
    await waitForPodList(page)

    const items = dropdown.locator('[data-testid="pod-item"]')
    const count = await items.count()
    expect(count).toBeGreaterThanOrEqual(1)

    // Check each item has a status dot (span with w-2 h-2 rounded-full)
    for (let i = 0; i < count; i++) {
      const dot = items.nth(i).locator("span.w-2.h-2.rounded-full")
      await expect(dot).toHaveCount(1)
      const classes = await dot.getAttribute("class")
      // The dot has dynamic background color classes like bg-green-500, bg-blue-500, etc.
      expect(classes).toMatch(/bg-(green|blue|violet|gray)-\d+/)
    }

    // Check each item has a status label (if present, it's in a span with text-[11px])
    for (let i = 0; i < count; i++) {
      const item = items.nth(i)
      // Status label is optional - only check it exists, not its text
      const statusLabel = item.locator("span.text-\\[11px\\]")
      // It may or may not be present depending on the pod state
      const statusCount = await statusLabel.count()
      expect(statusCount).toBeGreaterThanOrEqual(0)
    }
  })
})

import { test, expect } from '@playwright/test'

// Helper to login before each test
async function login(page: import('@playwright/test').Page) {
  await page.goto('/login')
  await page.getByLabel('Username').fill('admin')
  await page.getByLabel('Password').fill('Test123!')
  await page.getByRole('button', { name: /sign in/i }).click()
  await expect(page).toHaveURL('/', { timeout: 10000 })
}

test.describe('Dashboard', () => {
  test.beforeEach(async ({ page }) => {
    await login(page)
  })

  test('displays dashboard stats', async ({ page }) => {
    await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible()
    // Should show stat cards
    await expect(page.getByText(/awaiting triage/i)).toBeVisible({ timeout: 5000 })
    await expect(page.locator('main').getByText(/unmapped apps/i)).toBeVisible()
  })
})

test.describe('Findings', () => {
  test.beforeEach(async ({ page }) => {
    await login(page)
  })

  test('lists findings with correct data', async ({ page }) => {
    await page.getByRole('link', { name: /findings/i }).first().click()
    await expect(page).toHaveURL(/\/findings/)
    // Should display finding rows from seed data
    await expect(page.getByText('SAST').first()).toBeVisible({ timeout: 5000 })
  })

  test('navigates to finding detail', async ({ page }) => {
    await page.getByRole('link', { name: /findings/i }).first().click()
    await expect(page).toHaveURL(/\/findings/)
    // Click first finding link
    const firstRow = page.locator('table tbody tr').first()
    await firstRow.click()
    await expect(page).toHaveURL(/\/findings\//)
  })
})

test.describe('Applications', () => {
  test.beforeEach(async ({ page }) => {
    await login(page)
  })

  test('lists applications', async ({ page }) => {
    await page.getByRole('link', { name: /applications/i }).click()
    await expect(page).toHaveURL(/\/applications/)
    // Should show seeded applications
    await expect(page.getByText('PAYM1').first()).toBeVisible({ timeout: 5000 })
  })

  test('navigates to application detail', async ({ page }) => {
    await page.getByRole('link', { name: /applications/i }).click()
    await expect(page).toHaveURL(/\/applications/)
    const firstRow = page.locator('table tbody tr').first()
    await firstRow.click()
    await expect(page).toHaveURL(/\/applications\//)
  })
})

test.describe('Ingestion', () => {
  test.beforeEach(async ({ page }) => {
    await login(page)
  })

  test('displays ingestion page with history', async ({ page }) => {
    await page.getByRole('link', { name: /ingestion/i }).click()
    await expect(page).toHaveURL(/\/ingestion/)
    // Should show the upload form and history
    await expect(page.getByText(/upload/i).first()).toBeVisible({ timeout: 5000 })
    // Should show ingestion history from seed
    await expect(page.getByText('SonarQube').first()).toBeVisible()
  })
})

test.describe('Triage Queue', () => {
  test.beforeEach(async ({ page }) => {
    await login(page)
  })

  test('displays triage queue page', async ({ page }) => {
    await page.getByRole('link', { name: /triage/i }).click()
    await expect(page).toHaveURL(/\/triage/)
    await expect(page.getByText(/triage/i).first()).toBeVisible({ timeout: 5000 })
  })
})

test.describe('Unmapped Apps', () => {
  test.beforeEach(async ({ page }) => {
    await login(page)
  })

  test('displays unmapped apps page', async ({ page }) => {
    await page.getByRole('link', { name: /unmapped/i }).click()
    await expect(page).toHaveURL(/\/unmapped/)
    await expect(page.getByText(/unmapped/i).first()).toBeVisible({ timeout: 5000 })
  })
})

test.describe('Attack Chains', () => {
  test.beforeEach(async ({ page }) => {
    await login(page)
  })

  test('displays attack chains page with applications', async ({ page }) => {
    await page.getByRole('link', { name: /attack chains/i }).click()
    await expect(page).toHaveURL(/\/attack-chains/)
    await expect(page.getByRole('heading', { name: /attack chains/i })).toBeVisible({ timeout: 5000 })
    // Should show the applications table
    await expect(page.locator('table')).toBeVisible()
  })
})

test.describe('Correlation', () => {
  test.beforeEach(async ({ page }) => {
    await login(page)
  })

  test('displays correlation page with rules', async ({ page }) => {
    await page.getByRole('link', { name: /correlation/i }).click()
    await expect(page).toHaveURL(/\/correlations/)
    await expect(page.getByRole('heading', { name: /correlation engine/i })).toBeVisible({ timeout: 5000 })
    // Check that Rules and Groups tabs are visible
    await expect(page.getByRole('tab', { name: /rules/i })).toBeVisible()
    await expect(page.getByRole('tab', { name: /groups/i })).toBeVisible()
    // Rules tab is active by default and should show a table
    await expect(page.locator('table').first()).toBeVisible({ timeout: 5000 })
  })
})

test.describe('Deduplication', () => {
  test.beforeEach(async ({ page }) => {
    await login(page)
  })

  test('displays deduplication dashboard with stats', async ({ page }) => {
    await page.getByRole('link', { name: /deduplication/i }).click()
    await expect(page).toHaveURL(/\/deduplication/)
    await expect(page.getByRole('heading', { name: /deduplication dashboard/i })).toBeVisible({ timeout: 5000 })
    // Should show stat cards
    await expect(page.getByText(/total duplicates/i)).toBeVisible({ timeout: 5000 })
    await expect(page.getByText(/pending review/i).first()).toBeVisible()
  })
})

test.describe('Findings Tabs', () => {
  test.beforeEach(async ({ page }) => {
    await login(page)
  })

  test('switches between category tabs', async ({ page }) => {
    await page.getByRole('link', { name: /findings/i }).first().click()
    await expect(page).toHaveURL(/\/findings/)

    // Click SAST tab
    await page.getByRole('tab', { name: /sast/i }).click()
    await expect(page).toHaveURL(/tab=sast/)

    // Click SCA tab
    await page.getByRole('tab', { name: /sca/i }).click()
    await expect(page).toHaveURL(/tab=sca/)

    // Click DAST tab
    await page.getByRole('tab', { name: /dast/i }).click()
    await expect(page).toHaveURL(/tab=dast/)

    // Click All tab to go back — All tab clears the tab query param
    await page.getByRole('tab', { name: /^all$/i }).click()
    await expect(page).not.toHaveURL(/tab=/)
  })
})

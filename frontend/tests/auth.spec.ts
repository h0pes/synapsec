import { test, expect } from '@playwright/test'

test.describe('Authentication', () => {
  test('shows login page when not authenticated', async ({ page }) => {
    await page.goto('/')
    await expect(page).toHaveURL(/\/login/)
    await expect(page.getByText('SynApSec')).toBeVisible()
    await expect(page.getByLabel('Username')).toBeVisible()
    await expect(page.getByLabel('Password')).toBeVisible()
  })

  test('login with valid credentials redirects to dashboard', async ({ page }) => {
    await page.goto('/login')
    await page.getByLabel('Username').fill('admin')
    await page.getByLabel('Password').fill('Test123!')
    await page.getByRole('button', { name: /sign in/i }).click()

    await expect(page).toHaveURL('/', { timeout: 10000 })
    await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible()
  })

  test('login with invalid credentials shows error', async ({ page }) => {
    await page.goto('/login')
    await page.getByLabel('Username').fill('admin')
    await page.getByLabel('Password').fill('wrong-password')
    await page.getByRole('button', { name: /sign in/i }).click()

    await expect(page.getByText(/authentication required|unexpected|invalid/i)).toBeVisible({ timeout: 5000 })
  })

  test('logout clears session and redirects to login', async ({ page }) => {
    // Login first
    await page.goto('/login')
    await page.getByLabel('Username').fill('admin')
    await page.getByLabel('Password').fill('Test123!')
    await page.getByRole('button', { name: /sign in/i }).click()
    await expect(page).toHaveURL('/', { timeout: 10000 })

    // Open user menu and click logout
    await page.getByText('Platform Administrator').click()
    await page.getByText(/logout|sign out/i).click()

    await expect(page).toHaveURL(/\/login/, { timeout: 5000 })
  })
})

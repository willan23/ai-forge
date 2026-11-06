import { expect, test } from '@playwright/test';

test.describe('login page', () => {
  test('renders demo login form', async ({ page }) => {
    await page.goto('/login');
    await expect(page.getByRole('heading', { name: 'Entrar' })).toBeVisible();
    await expect(page.locator('input[name="email"]')).toHaveValue('admin@demo.local');
    await expect(page.getByText('admin@demo.local / demo-admin')).toBeVisible();
  });

  test('rejects invalid credentials', async ({ page }) => {
    await page.goto('/login');
    await page.locator('input[name="email"]').fill('admin@demo.local');
    await page.locator('input[name="password"]').fill('wrong-password');
    await page.getByRole('button', { name: 'Entrar' }).click();
    await expect(page.locator('.login-error')).toContainText(/incorrectos|inválidas/i);
    await expect(page).toHaveURL(/\/login/);
  });

  test('signs in with demo admin and lands on overview', async ({ page }) => {
    await page.goto('/login');
    await page.locator('input[name="email"]').fill('admin@demo.local');
    await page.locator('input[name="password"]').fill('demo-admin');
    await page.getByRole('button', { name: 'Entrar' }).click();
    await expect(page).toHaveURL('/');
    await expect(page.getByRole('heading', { name: 'Overview' })).toBeVisible();
  });

  test('switches to Self-Serve SaaS registration tab', async ({ page }) => {
    await page.goto('/login');
    await page.getByRole('button', { name: /Criar Empresa \(Self-Serve SaaS\)/i }).click();
    await expect(page.getByRole('heading', { name: /Registar Organização SaaS/i })).toBeVisible();
    await expect(page.locator('input[name="organizationName"]')).toBeVisible();
  });
});

import { expect, test } from '@playwright/test';

test.describe('login page', () => {
  test('renders enterprise login form without pre-filled demo credentials', async ({ page }) => {
    await page.goto('/login');
    await expect(page.getByRole('heading', { name: 'Entrar' })).toBeVisible();
    await expect(page.locator('input[name="email"]')).toHaveValue('');
    await expect(page.getByText(/KDF scrypt/i).first()).toBeVisible();
  });

  test('rejects invalid credentials', async ({ page }) => {
    await page.goto('/login');
    await page.locator('input[name="email"]').fill('ciso@wgf.security');
    await page.locator('input[name="password"]').fill('wrong-password');
    await page.getByRole('button', { name: 'Entrar' }).click();
    await expect(page.locator('.login-error')).toContainText(/incorrectos|inválidas/i);
    await expect(page).toHaveURL(/\/login/);
  });

  test('signs in with enterprise CISO account and lands on overview', async ({ page }) => {
    await page.goto('/login');
    await page.locator('input[name="email"]').fill('ciso@wgf.security');
    await page.locator('input[name="password"]').fill('WgfSec!2026');
    await page.getByRole('button', { name: 'Entrar' }).click();
    await expect(page).toHaveURL('/');
    await expect(page.getByRole('heading', { name: 'Overview' })).toBeVisible();
  });

  test('registers a new Self-Serve SaaS organization and logs in', async ({ page }) => {
    await page.goto('/login');
    await page.getByRole('button', { name: /Criar Empresa \(Self-Serve SaaS\)/i }).click();
    await expect(page.getByRole('heading', { name: /Registar Organização SaaS/i })).toBeVisible();
    const uniqueEmail = `ciso.${Date.now()}@fintech-europa.pt`;
    await page.locator('input[name="fullName"]').fill('Helena Costa (CISO)');
    await page.locator('input[name="organizationName"]').fill('Fintech Europa S.A.');
    await page.locator('input[name="registerEmail"]').fill(uniqueEmail);
    await page.locator('input[name="registerPassword"]').fill('StrongPass!2026');
    await page.getByRole('button', { name: /Criar Empresa & Entrar/i }).click();
    await expect(page).toHaveURL('/', { timeout: 15000 });
    await expect(page.getByRole('heading', { name: 'Overview' })).toBeVisible();
  });
});

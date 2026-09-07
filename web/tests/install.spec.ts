import { expect, test } from '@playwright/test'
import { CSRF_COOKIE, CSRF_HEADER } from '../src/api'
import {
  ACCOUNT_OBJECT_KEYS,
  CONFIG_OBJECT_KEYS,
  TEST_PASSWORD,
  dashboardAccount,
  dashboardConfig,
  dashboardStatus,
  emptyHistory,
  expectKnownKeys,
  jobFixture,
  mockDashboardReads,
  mockInitStatus,
  mockUnauthorizedSession,
} from './harness'

async function expectNoHorizontalOverflow(page: import('@playwright/test').Page) {
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)
  expect(overflow).toBeLessThanOrEqual(1)
}

test('installation wizard posts the setup contract and reaches the dashboard', async ({ page }, testInfo) => {
  await mockInitStatus(page, false)
  let setupBody: Record<string, unknown> | undefined
  await page.route('**/api/v1/setup', async (route) => {
    expect(route.request().method()).toBe('POST')
    setupBody = JSON.parse(route.request().postData() || '{}') as Record<string, unknown>
    await route.fulfill({ status: 201, json: { success: true, csrf_token: 'test-csrf' } })
  })
  await mockDashboardReads(page)

  await page.goto('/')
  await expect(page.getByRole('heading', { name: '创建安全边界' })).toBeVisible()
  await expectNoHorizontalOverflow(page)
  await page.screenshot({ path: testInfo.outputPath('setup-desktop.png'), fullPage: true })

  await page.setViewportSize({ width: 390, height: 844 })
  await expectNoHorizontalOverflow(page)
  await page.screenshot({ path: testInfo.outputPath('setup-mobile.png'), fullPage: true })

  await page.setViewportSize({ width: 1440, height: 1000 })
  const passwords = page.locator('input[type="password"]')
  await passwords.nth(0).fill(TEST_PASSWORD)
  await passwords.nth(1).fill(TEST_PASSWORD)
  await page.getByRole('button', { name: '继续' }).click()
  await expect(page.getByRole('heading', { name: '设定自动化策略' })).toBeVisible()
  await page.getByRole('button', { name: '继续' }).click()
  await expect(page.getByRole('heading', { name: '连接云端实例' })).toBeVisible()
  await page.getByRole('button', { name: '完成安装' }).click()

  await expect(page.getByRole('heading', { name: '资源控制台' })).toBeVisible({ timeout: 30_000 })
  expect(setupBody).toBeTruthy()
  expectKnownKeys(setupBody!, CONFIG_OBJECT_KEYS)
  expect(setupBody).toMatchObject({
    admin_password: TEST_PASSWORD,
    traffic_threshold: 95,
    enable_schedule_notification: false,
    shutdown_mode: 'KeepCharging',
    threshold_action: 'stop_and_notify',
    keep_alive: false,
    api_interval: 600,
    enable_billing: false,
    timezone: 'Asia/Shanghai',
    accounts: [],
  })
  const notifications = setupBody!.notifications as Record<string, Record<string, unknown>>
  expect(notifications.email).toMatchObject({ enabled: false, port: 465, security: 'ssl', password_configured: false })
  expect(notifications.telegram).toMatchObject({ enabled: false, token_configured: false, proxy_type: 'none', proxy_password_configured: false })
  expect(notifications.webhook).toMatchObject({ enabled: false, method: 'GET', request_type: 'JSON', secret_configured: false })
  await expectNoHorizontalOverflow(page)
  await page.screenshot({ path: testInfo.outputPath('dashboard-desktop.png'), fullPage: true })

  await page.setViewportSize({ width: 390, height: 844 })
  await expectNoHorizontalOverflow(page)
  await page.screenshot({ path: testInfo.outputPath('dashboard-mobile.png'), fullPage: true })
})

test('secure login authenticates with the password contract', async ({ page }, testInfo) => {
  await mockInitStatus(page, true)
  let authed = false
  await page.route('**/api/v1/auth/login', async (route) => {
    expect(route.request().method()).toBe('POST')
    expect(JSON.parse(route.request().postData() || '{}')).toEqual({ password: TEST_PASSWORD })
    authed = true
    await route.fulfill({ json: { success: true, csrf_token: 'test-csrf' } })
  })
  await page.route('**/api/v1/status', (route) => {
    if (!authed) return route.fulfill({ status: 401, json: { error: { code: 'unauthorized', message: '请登录或提供有效 API Key' } } })
    return route.fulfill({ json: dashboardStatus })
  })
  await page.route('**/api/v1/config', (route) => {
    if (!authed) return route.fulfill({ status: 401, json: { error: { code: 'unauthorized', message: '请登录或提供有效 API Key' } } })
    return route.fulfill({ json: dashboardConfig })
  })

  await page.goto('/')
  await expect(page.getByRole('heading', { name: '欢迎回来' })).toBeVisible()
  await expectNoHorizontalOverflow(page)
  await page.screenshot({ path: testInfo.outputPath('login-desktop.png'), fullPage: true })

  await page.setViewportSize({ width: 390, height: 844 })
  await expectNoHorizontalOverflow(page)
  await page.screenshot({ path: testInfo.outputPath('login-mobile.png'), fullPage: true })

  await page.getByLabel('管理员密码').fill(TEST_PASSWORD)
  await page.getByRole('button', { name: '安全登录' }).click()
  await expect(page.getByRole('heading', { name: '资源控制台' })).toBeVisible({ timeout: 30_000 })
})

test('login surfaces the API invalid-credentials envelope', async ({ page }) => {
  await mockInitStatus(page, true)
  await mockUnauthorizedSession(page)
  await page.route('**/api/v1/auth/login', (route) => route.fulfill({
    status: 401,
    json: { error: { code: 'invalid_credentials', message: '密码错误' } },
  }))

  await page.goto('/')
  await page.getByLabel('管理员密码').fill(TEST_PASSWORD)
  await page.getByRole('button', { name: '安全登录' }).click()
  await expect(page.getByText('密码错误')).toBeVisible()
  await expect(page.getByRole('heading', { name: '欢迎回来' })).toBeVisible()
})

test('history chart renders empty sampling state from the history contract', async ({ page }) => {
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/accounts/1/history', (route) => route.fulfill({ json: emptyHistory }))

  await page.goto('/')
  await page.getByRole('button', { name: '查看历史流量' }).click()
  await expect(page.getByText('等待采样数据')).toBeVisible()
})

test('setup account payload only uses documented account fields', async ({ page }) => {
  await mockInitStatus(page, false)
  let account: Record<string, unknown> | undefined
  await page.route('**/api/v1/setup', async (route) => {
    const body = JSON.parse(route.request().postData() || '{}') as { accounts?: Record<string, unknown>[] }
    account = body.accounts?.[0]
    expectKnownKeys(body, CONFIG_OBJECT_KEYS)
    if (account) expectKnownKeys(account, ACCOUNT_OBJECT_KEYS)
    await route.fulfill({ status: 201, json: { success: true, csrf_token: 'test-csrf' } })
  })
  await mockDashboardReads(page)

  await page.goto('/')
  const passwords = page.locator('input[type="password"]')
  await passwords.nth(0).fill(TEST_PASSWORD)
  await passwords.nth(1).fill(TEST_PASSWORD)
  await page.getByRole('button', { name: '继续' }).click()
  await page.getByRole('button', { name: '继续' }).click()
  await page.getByLabel('AccessKey ID').fill('LTAI5contract')
  await page.getByLabel('实例 ID').fill('i-contract')
  await page.getByRole('button', { name: '完成安装' }).click()
  await expect(page.getByRole('heading', { name: '资源控制台' })).toBeVisible({ timeout: 30_000 })
  expect(account).toMatchObject({
    access_key_id: 'LTAI5contract',
    instance_id: 'i-contract',
    region_id: 'cn-hongkong',
    site_type: 'china',
    max_traffic: 200,
    secret_configured: false,
  })
})

test('refresh-all sends the CSRF header from the cdt_csrf cookie', async ({ page }) => {
  const csrf = 'test-csrf'
  await mockInitStatus(page, true)
  let authed = false
  let refreshCsrf = ''
  await page.route('**/api/v1/auth/login', async (route) => {
    authed = true
    await route.fulfill({ json: { success: true, csrf_token: csrf } })
  })
  await page.route('**/api/v1/status', (route) => {
    if (!authed) return route.fulfill({ status: 401, json: { error: { code: 'unauthorized', message: '请登录或提供有效 API Key' } } })
    return route.fulfill({ json: dashboardStatus })
  })
  await page.route('**/api/v1/config', (route) => {
    if (!authed) return route.fulfill({ status: 401, json: { error: { code: 'unauthorized', message: '请登录或提供有效 API Key' } } })
    return route.fulfill({ json: dashboardConfig })
  })
  await page.route('**/api/v1/accounts/refresh', (route) => {
    expect(route.request().method()).toBe('POST')
    refreshCsrf = route.request().headers()[CSRF_HEADER.toLowerCase()] || ''
    return route.fulfill({ status: 202, json: { jobs: [jobFixture('refresh-1', 'queued')] } })
  })
  await page.route('**/api/v1/jobs/**', (route) => {
    const id = route.request().url().split('/').pop() || 'refresh-1'
    return route.fulfill({ json: jobFixture(id, 'completed') })
  })

  await page.goto('/')
  await page.getByLabel('管理员密码').fill(TEST_PASSWORD)
  await page.getByRole('button', { name: '安全登录' }).click()
  await expect(page.getByRole('heading', { name: '资源控制台' })).toBeVisible({ timeout: 30_000 })
  await page.context().addCookies([{ name: CSRF_COOKIE, value: csrf, url: page.url() }])
  await page.getByRole('button', { name: '强制刷新全部实例' }).click()
  await expect(page.getByText('已强制刷新 1 个实例')).toBeVisible()
  expect(refreshCsrf).toBe(csrf)
})


test('wizard keeps step one until the password contract is met', async ({ page }) => {
  await mockInitStatus(page, false)
  await page.goto('/')
  await expect(page.getByRole('heading', { name: '创建安全边界' })).toBeVisible()
  const passwords = page.locator('input[type="password"]')
  await passwords.nth(0).fill('short')
  await passwords.nth(1).fill('short')
  await page.getByRole('button', { name: '继续' }).click()
  await expect(page.getByText('管理员密码至少需要 10 个字符')).toBeVisible()
  await expect(page.getByRole('heading', { name: '创建安全边界' })).toBeVisible()

  await passwords.nth(0).fill(TEST_PASSWORD)
  await passwords.nth(1).fill('Different-Password-42!')
  await page.getByRole('button', { name: '继续' }).click()
  await expect(page.getByText('两次输入的密码不一致')).toBeVisible()
  await expect(page.getByRole('heading', { name: '创建安全边界' })).toBeVisible()

  await passwords.nth(1).fill(TEST_PASSWORD)
  await page.getByRole('button', { name: '继续' }).click()
  await expect(page.getByRole('heading', { name: '设定自动化策略' })).toBeVisible()
})

test('login surfaces lock and rate-limit envelopes', async ({ page }) => {
  await mockInitStatus(page, true)
  await mockUnauthorizedSession(page)
  let attempt = 0
  await page.route('**/api/v1/auth/login', (route) => {
    attempt += 1
    if (attempt === 1) {
      return route.fulfill({ status: 429, json: { error: { code: 'rate_limited', message: '登录尝试过多，请稍后再试' } } })
    }
    return route.fulfill({ status: 429, json: { error: { code: 'login_locked', message: '登录已临时锁定 15 分钟' } } })
  })

  await page.goto('/')
  await page.getByLabel('管理员密码').fill(TEST_PASSWORD)
  await page.getByRole('button', { name: '安全登录' }).click()
  await expect(page.getByText('登录尝试过多，请稍后再试')).toBeVisible()
  await expect(page.getByRole('heading', { name: '欢迎回来' })).toBeVisible()
  await page.getByRole('button', { name: '安全登录' }).click()
  await expect(page.getByText('登录已临时锁定 15 分钟')).toBeVisible()
  await expect(page.getByRole('heading', { name: '欢迎回来' })).toBeVisible()
})

test('history chart surfaces the history_failed envelope', async ({ page }) => {
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/accounts/1/history', (route) => route.fulfill({
    status: 500,
    json: { error: { code: 'history_failed', message: '历史流量加载失败' } },
  }))

  await page.goto('/')
  await page.getByRole('button', { name: '查看历史流量' }).click()
  await expect(page.getByRole('alert')).toContainText('历史流量加载失败')
  await expect(page.locator('.chart-area .recharts-wrapper')).toHaveCount(0)
})


test('wizard surfaces the setup_failed envelope and stays on install', async ({ page }) => {
  await mockInitStatus(page, false)
  await page.route('**/api/v1/setup', (route) => route.fulfill({
    status: 400,
    json: { error: { code: 'setup_failed', message: 'system is already initialized' } },
  }))

  await page.goto('/')
  const passwords = page.locator('input[type="password"]')
  await passwords.nth(0).fill(TEST_PASSWORD)
  await passwords.nth(1).fill(TEST_PASSWORD)
  await page.getByRole('button', { name: '继续' }).click()
  await page.getByRole('button', { name: '继续' }).click()
  await page.getByRole('button', { name: '完成安装' }).click()
  await expect(page.getByText('system is already initialized')).toBeVisible()
  await expect(page.getByRole('heading', { name: '连接云端实例' })).toBeVisible()
})


test('history chart labels follow config timezone', async ({ page }) => {
  const hourStart = Math.floor(Date.now() / 3_600_000) * 3_600_000
  await mockInitStatus(page, true)
  await mockDashboardReads(page, dashboardStatus, { ...dashboardConfig, timezone: 'Asia/Shanghai' })
  await page.route('**/api/v1/accounts/1/history', (route) => route.fulfill({ json: {
    hourly: [{ at: new Date(hourStart).toISOString(), traffic: 1.23456 }],
    daily: [{ at: new Date(hourStart).toISOString(), traffic: 9.87654 }],
  } }))

  await page.goto('/')
  await page.getByRole('button', { name: '查看历史流量' }).click()
  const expectedHour = await page.evaluate(
    (timestamp) => new Date(timestamp).toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit', hour12: false, timeZone: 'Asia/Shanghai' }),
    hourStart,
  )
  const latestSample = page.locator('.chart-area .recharts-line-dot').last()
  await expect(latestSample).toBeVisible()
  await latestSample.hover()
  await expect(page.getByText('1.235')).toBeVisible()
  await expect(page.locator('.recharts-tooltip-label')).toHaveText(expectedHour)

  await page.getByRole('button', { name: '30 天' }).click()
  const expectedDay = await page.evaluate(
    (timestamp) => new Date(timestamp).toLocaleDateString('zh-CN', { month: 'numeric', day: 'numeric', timeZone: 'Asia/Shanghai' }),
    hourStart,
  )
  const sparseBar = page.locator('.recharts-bar-rectangle .recharts-rectangle').first()
  await expect(sparseBar).toBeVisible()
  await sparseBar.hover()
  await expect(page.locator('.recharts-tooltip-label')).toHaveText(expectedDay)
})


test('dashboard timestamps follow config timezone', async ({ page }) => {
  const at = '2026-09-07T16:00:00.000Z'
  await mockInitStatus(page, true)
  await mockDashboardReads(page, {
    ...dashboardStatus,
    system_last_run: at,
    accounts: [{ ...dashboardAccount, last_updated: at }],
  }, { ...dashboardConfig, timezone: 'Asia/Shanghai' })

  await page.goto('/')
  const expected = await page.evaluate(
    (timestamp) => new Date(timestamp).toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit', hour12: false, timeZone: 'Asia/Shanghai' }),
    at,
  )
  await expect(page.locator('.overview-time b')).toHaveText(expected)
  await expect(page.locator('.account-card__footer')).toContainText(expected)
})

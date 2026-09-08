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
    json: { error: { code: 'history_failed', message: '历史记录加载失败' } },
  }))

  await page.goto('/')
  await page.getByRole('button', { name: '查看历史流量' }).click()
  await expect(page.getByRole('alert')).toContainText('历史记录加载失败')
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


test('settings dates follow config timezone', async ({ page }) => {
  const at = '2026-09-07T16:00:00.000Z'
  await mockInitStatus(page, true)
  await mockDashboardReads(page, dashboardStatus, { ...dashboardConfig, timezone: 'Asia/Shanghai' })
  await page.route('**/api/v1/logs**', (route) => {
    if (route.request().method() === 'DELETE') return route.fulfill({ json: { success: true } })
    return route.fulfill({ json: { logs: [{ id: 1, type: 'audit', message: '时区日志', created_at: at }] } })
  })
  await page.route('**/api/v1/api-keys', (route) => route.fulfill({ json: {
    keys: [{ id: 1, name: '桌面小组件', scopes: ['widget:read'], created_at: at }],
  } }))
  await page.route('**/api/v1/admin/passkeys', (route) => route.fulfill({ json: {
    passkeys: [{ id: 1, name: '办公室电脑', created_at: at }],
  } }))

  await page.goto('/')
  const expected = await page.evaluate(
    (timestamp) => new Date(timestamp).toLocaleString('zh-CN', { month: 'numeric', day: 'numeric', hour: '2-digit', minute: '2-digit', hour12: false, timeZone: 'Asia/Shanghai' }),
    at,
  )
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '日志' }).click()
  await expect(page.getByText('时区日志')).toBeVisible()
  await expect(page.locator('.log-row span')).toContainText(expected)

  await page.getByRole('button', { name: 'API Key' }).click()
  await expect(page.getByText('桌面小组件')).toBeVisible()
  await expect(page.locator('.key-row time')).toContainText(expected)
  await page.locator('.settings-panel').getByRole('button', { name: '关闭' }).click()

  await page.getByRole('button', { name: '管理员' }).click()
  await expect(page.getByText('办公室电脑')).toBeVisible()
  await expect(page.locator('.passkey-row')).toContainText(expected)
})


test('about built_at uses config timezone when it is a timestamp', async ({ page }) => {
  const at = '2026-09-07T16:00:00.000Z'
  await mockInitStatus(page, true)
  await mockDashboardReads(page, dashboardStatus, { ...dashboardConfig, timezone: 'Asia/Shanghai' })
  await page.route('**/api/v1/system/info**', (route) => route.fulfill({ json: {
    version: 'v2.0.1',
    commit: 'abc1234',
    built_at: at,
    repository: 'https://github.com/wang4386/CDT-Monitor',
    release_url: 'https://github.com/wang4386/CDT-Monitor/releases',
  } }))

  await page.goto('/')
  const expected = await page.evaluate(
    (timestamp) => new Date(timestamp).toLocaleString('zh-CN', { month: 'numeric', day: 'numeric', hour: '2-digit', minute: '2-digit', hour12: false, timeZone: 'Asia/Shanghai' }),
    at,
  )
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '关于' }).click()
  await expect(page.locator('.about-version small')).toHaveText(`abc1234 · ${expected}`)
})

test('about built_at keeps opaque build stamps', async ({ page }) => {
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/system/info**', (route) => route.fulfill({ json: {
    version: 'v2.0.1',
    commit: 'abc1234',
    built_at: 'github-run-12345',
    repository: 'https://github.com/wang4386/CDT-Monitor',
    release_url: 'https://github.com/wang4386/CDT-Monitor/releases',
  } }))

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '关于' }).click()
  await expect(page.locator('.about-version small')).toHaveText('abc1234 · github-run-12345')
})


test('setup posts the chosen timezone', async ({ page }) => {
  await mockInitStatus(page, false)
  let timezone = ''
  await page.route('**/api/v1/setup', async (route) => {
    const body = JSON.parse(route.request().postData() || '{}') as { timezone?: string }
    timezone = body.timezone || ''
    expectKnownKeys(body, CONFIG_OBJECT_KEYS)
    await route.fulfill({ status: 201, json: { success: true, csrf_token: 'test-csrf' } })
  })
  await mockDashboardReads(page)

  await page.goto('/')
  const passwords = page.locator('input[type="password"]')
  await passwords.nth(0).fill(TEST_PASSWORD)
  await passwords.nth(1).fill(TEST_PASSWORD)
  await page.getByRole('button', { name: '继续' }).click()
  await expect(page.getByRole('heading', { name: '设定自动化策略' })).toBeVisible()
  await expect(page.getByLabel('系统时区')).toHaveValue('Asia/Shanghai')
  await page.getByLabel('系统时区').fill('Asia/Taipei')
  await page.getByRole('button', { name: '继续' }).click()
  await page.getByRole('button', { name: '完成安装' }).click()
  await expect(page.getByRole('heading', { name: '资源控制台' })).toBeVisible({ timeout: 30_000 })
  expect(timezone).toBe('Asia/Taipei')
})


test('setup posts notify_only threshold action', async ({ page }) => {
  await mockInitStatus(page, false)
  let thresholdAction = ''
  await page.route('**/api/v1/setup', async (route) => {
    const body = JSON.parse(route.request().postData() || '{}') as { threshold_action?: string }
    thresholdAction = body.threshold_action || ''
    expectKnownKeys(body, CONFIG_OBJECT_KEYS)
    await route.fulfill({ status: 201, json: { success: true, csrf_token: 'test-csrf' } })
  })
  await mockDashboardReads(page)

  await page.goto('/')
  const passwords = page.locator('input[type="password"]')
  await passwords.nth(0).fill(TEST_PASSWORD)
  await passwords.nth(1).fill(TEST_PASSWORD)
  await page.getByRole('button', { name: '继续' }).click()
  await expect(page.getByRole('heading', { name: '设定自动化策略' })).toBeVisible()
  await page.getByRole('button', { name: '仅通知' }).click()
  await page.getByRole('button', { name: '继续' }).click()
  await page.getByRole('button', { name: '完成安装' }).click()
  await expect(page.getByRole('heading', { name: '资源控制台' })).toBeVisible({ timeout: 30_000 })
  expect(thresholdAction).toBe('notify_only')
})


test('setup posts schedule notification enabled', async ({ page }) => {
  await mockInitStatus(page, false)
  let enabled: boolean | undefined
  await page.route('**/api/v1/setup', async (route) => {
    const body = JSON.parse(route.request().postData() || '{}') as { enable_schedule_notification?: boolean }
    enabled = body.enable_schedule_notification
    expectKnownKeys(body, CONFIG_OBJECT_KEYS)
    await route.fulfill({ status: 201, json: { success: true, csrf_token: 'test-csrf' } })
  })
  await mockDashboardReads(page)

  await page.goto('/')
  const passwords = page.locator('input[type="password"]')
  await passwords.nth(0).fill(TEST_PASSWORD)
  await passwords.nth(1).fill(TEST_PASSWORD)
  await page.getByRole('button', { name: '继续' }).click()
  await expect(page.getByRole('heading', { name: '设定自动化策略' })).toBeVisible()
  await page.getByText('定时任务通知', { exact: true }).click()
  await page.getByRole('button', { name: '继续' }).click()
  await page.getByRole('button', { name: '完成安装' }).click()
  await expect(page.getByRole('heading', { name: '资源控制台' })).toBeVisible({ timeout: 30_000 })
  expect(enabled).toBe(true)
})


test('invalid timezone falls back to Asia/Shanghai on charts and dashboard', async ({ page }) => {
  const hourStart = Math.floor(Date.now() / 3_600_000) * 3_600_000
  const at = new Date(hourStart).toISOString()
  await mockInitStatus(page, true)
  await mockDashboardReads(page, {
    ...dashboardStatus,
    system_last_run: at,
    accounts: [{ ...dashboardAccount, last_updated: at }],
  }, { ...dashboardConfig, timezone: 'Not/AZone' })
  await page.route('**/api/v1/accounts/1/history', (route) => route.fulfill({ json: {
    hourly: [{ at, traffic: 1.23456 }],
    daily: [],
  } }))

  await page.goto('/')
  const expected = await page.evaluate(
    (timestamp) => new Date(timestamp).toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit', hour12: false, timeZone: 'Asia/Shanghai' }),
    hourStart,
  )
  await expect(page.locator('.overview-time b')).toHaveText(expected)
  await expect(page.locator('.account-card__footer')).toContainText(expected)

  await page.getByRole('button', { name: '查看历史流量' }).click()
  const latestSample = page.locator('.chart-area .recharts-line-dot').last()
  await expect(latestSample).toBeVisible()
  await latestSample.hover()
  await expect(page.getByText('1.235')).toBeVisible()
  await expect(page.locator('.recharts-tooltip-label')).toHaveText(expected)
})


test('setup posts keep_alive enabled', async ({ page }) => {
  await mockInitStatus(page, false)
  let keepAlive: boolean | undefined
  await page.route('**/api/v1/setup', async (route) => {
    const body = JSON.parse(route.request().postData() || '{}') as { keep_alive?: boolean }
    keepAlive = body.keep_alive
    expectKnownKeys(body, CONFIG_OBJECT_KEYS)
    await route.fulfill({ status: 201, json: { success: true, csrf_token: 'test-csrf' } })
  })
  await mockDashboardReads(page)

  await page.goto('/')
  const passwords = page.locator('input[type="password"]')
  await passwords.nth(0).fill(TEST_PASSWORD)
  await passwords.nth(1).fill(TEST_PASSWORD)
  await page.getByRole('button', { name: '继续' }).click()
  await expect(page.getByRole('heading', { name: '设定自动化策略' })).toBeVisible()
  await page.getByText('抢占式实例保活', { exact: true }).click()
  await page.getByRole('button', { name: '继续' }).click()
  await page.getByRole('button', { name: '完成安装' }).click()
  await expect(page.getByRole('heading', { name: '资源控制台' })).toBeVisible({ timeout: 30_000 })
  expect(keepAlive).toBe(true)
})


test('setup posts enable_billing enabled', async ({ page }) => {
  await mockInitStatus(page, false)
  let enableBilling: boolean | undefined
  await page.route('**/api/v1/setup', async (route) => {
    const body = JSON.parse(route.request().postData() || '{}') as { enable_billing?: boolean }
    enableBilling = body.enable_billing
    expectKnownKeys(body, CONFIG_OBJECT_KEYS)
    await route.fulfill({ status: 201, json: { success: true, csrf_token: 'test-csrf' } })
  })
  await mockDashboardReads(page)

  await page.goto('/')
  const passwords = page.locator('input[type="password"]')
  await passwords.nth(0).fill(TEST_PASSWORD)
  await passwords.nth(1).fill(TEST_PASSWORD)
  await page.getByRole('button', { name: '继续' }).click()
  await expect(page.getByRole('heading', { name: '设定自动化策略' })).toBeVisible()
  await page.getByText('账单与余额显示', { exact: true }).click()
  await page.getByRole('button', { name: '继续' }).click()
  await page.getByRole('button', { name: '完成安装' }).click()
  await expect(page.getByRole('heading', { name: '资源控制台' })).toBeVisible({ timeout: 30_000 })
  expect(enableBilling).toBe(true)
})


test('setup posts StopCharging shutdown mode', async ({ page }) => {
  await mockInitStatus(page, false)
  let shutdownMode = ''
  await page.route('**/api/v1/setup', async (route) => {
    const body = JSON.parse(route.request().postData() || '{}') as { shutdown_mode?: string }
    shutdownMode = body.shutdown_mode || ''
    expectKnownKeys(body, CONFIG_OBJECT_KEYS)
    await route.fulfill({ status: 201, json: { success: true, csrf_token: 'test-csrf' } })
  })
  await mockDashboardReads(page)

  await page.goto('/')
  const passwords = page.locator('input[type="password"]')
  await passwords.nth(0).fill(TEST_PASSWORD)
  await passwords.nth(1).fill(TEST_PASSWORD)
  await page.getByRole('button', { name: '继续' }).click()
  await expect(page.getByRole('heading', { name: '设定自动化策略' })).toBeVisible()
  await page.getByRole('button', { name: '节省停机' }).click()
  await page.getByRole('button', { name: '继续' }).click()
  await page.getByRole('button', { name: '完成安装' }).click()
  await expect(page.getByRole('heading', { name: '资源控制台' })).toBeVisible({ timeout: 30_000 })
  expect(shutdownMode).toBe('StopCharging')
})


test('setup posts custom api_interval', async ({ page }) => {
  await mockInitStatus(page, false)
  let interval: number | undefined
  await page.route('**/api/v1/setup', async (route) => {
    const body = JSON.parse(route.request().postData() || '{}') as { api_interval?: number }
    interval = body.api_interval
    expectKnownKeys(body, CONFIG_OBJECT_KEYS)
    await route.fulfill({ status: 201, json: { success: true, csrf_token: 'test-csrf' } })
  })
  await mockDashboardReads(page)

  await page.goto('/')
  const passwords = page.locator('input[type="password"]')
  await passwords.nth(0).fill(TEST_PASSWORD)
  await passwords.nth(1).fill(TEST_PASSWORD)
  await page.getByRole('button', { name: '继续' }).click()
  await expect(page.getByRole('heading', { name: '设定自动化策略' })).toBeVisible()
  await page.getByRole('combobox', { name: '状态刷新频率' }).click()
  await page.getByRole('option', { name: '自定义' }).click()
  await page.getByLabel('自定义间隔').fill('45')
  await page.getByRole('button', { name: '继续' }).click()
  await page.getByRole('button', { name: '完成安装' }).click()
  await expect(page.getByRole('heading', { name: '资源控制台' })).toBeVisible({ timeout: 30_000 })
  expect(interval).toBe(45)
})


test('wizard surfaces the setup rate_limited envelope and stays on install', async ({ page }) => {
  await mockInitStatus(page, false)
  await page.route('**/api/v1/setup', (route) => route.fulfill({
    status: 429,
    json: { error: { code: 'rate_limited', message: '请求过于频繁' } },
  }))

  await page.goto('/')
  const passwords = page.locator('input[type="password"]')
  await passwords.nth(0).fill(TEST_PASSWORD)
  await passwords.nth(1).fill(TEST_PASSWORD)
  await page.getByRole('button', { name: '继续' }).click()
  await page.getByRole('button', { name: '继续' }).click()
  await page.getByRole('button', { name: '完成安装' }).click()
  await expect(page.getByText('请求过于频繁')).toBeVisible()
  await expect(page.getByRole('heading', { name: '连接云端实例' })).toBeVisible()
})


test('setup posts custom traffic_threshold', async ({ page }) => {
  await mockInitStatus(page, false)
  let threshold: number | undefined
  await page.route('**/api/v1/setup', async (route) => {
    const body = JSON.parse(route.request().postData() || '{}') as { traffic_threshold?: number }
    threshold = body.traffic_threshold
    expectKnownKeys(body, CONFIG_OBJECT_KEYS)
    await route.fulfill({ status: 201, json: { success: true, csrf_token: 'test-csrf' } })
  })
  await mockDashboardReads(page)

  await page.goto('/')
  const passwords = page.locator('input[type="password"]')
  await passwords.nth(0).fill(TEST_PASSWORD)
  await passwords.nth(1).fill(TEST_PASSWORD)
  await page.getByRole('button', { name: '继续' }).click()
  await expect(page.getByRole('heading', { name: '设定自动化策略' })).toBeVisible()
  await page.getByLabel('流量告警阈值').fill('80')
  await page.getByRole('button', { name: '继续' }).click()
  await page.getByRole('button', { name: '完成安装' }).click()
  await expect(page.getByRole('heading', { name: '资源控制台' })).toBeVisible({ timeout: 30_000 })
  expect(threshold).toBe(80)
})


test('setup posts international site_type', async ({ page }) => {
  await mockInitStatus(page, false)
  let siteType = ''
  await page.route('**/api/v1/setup', async (route) => {
    const body = JSON.parse(route.request().postData() || '{}') as { accounts?: { site_type?: string }[] }
    siteType = body.accounts?.[0]?.site_type || ''
    expectKnownKeys(body, CONFIG_OBJECT_KEYS)
    if (body.accounts?.[0]) expectKnownKeys(body.accounts[0], ACCOUNT_OBJECT_KEYS)
    await route.fulfill({ status: 201, json: { success: true, csrf_token: 'test-csrf' } })
  })
  await mockDashboardReads(page)

  await page.goto('/')
  const passwords = page.locator('input[type="password"]')
  await passwords.nth(0).fill(TEST_PASSWORD)
  await passwords.nth(1).fill(TEST_PASSWORD)
  await page.getByRole('button', { name: '继续' }).click()
  await page.getByRole('button', { name: '继续' }).click()
  await page.getByLabel('AccessKey ID').fill('LTAI5intl')
  await page.getByRole('combobox', { name: '站点类型' }).click()
  await page.getByRole('option', { name: /国际站/ }).click()
  await page.getByRole('button', { name: '完成安装' }).click()
  await expect(page.getByRole('heading', { name: '资源控制台' })).toBeVisible({ timeout: 30_000 })
  expect(siteType).toBe('international')
})


test('setup posts custom max_traffic', async ({ page }) => {
  await mockInitStatus(page, false)
  let maxTraffic: number | undefined
  await page.route('**/api/v1/setup', async (route) => {
    const body = JSON.parse(route.request().postData() || '{}') as { accounts?: { max_traffic?: number }[] }
    maxTraffic = body.accounts?.[0]?.max_traffic
    expectKnownKeys(body, CONFIG_OBJECT_KEYS)
    if (body.accounts?.[0]) expectKnownKeys(body.accounts[0], ACCOUNT_OBJECT_KEYS)
    await route.fulfill({ status: 201, json: { success: true, csrf_token: 'test-csrf' } })
  })
  await mockDashboardReads(page)

  await page.goto('/')
  const passwords = page.locator('input[type="password"]')
  await passwords.nth(0).fill(TEST_PASSWORD)
  await passwords.nth(1).fill(TEST_PASSWORD)
  await page.getByRole('button', { name: '继续' }).click()
  await page.getByRole('button', { name: '继续' }).click()
  await page.getByLabel('AccessKey ID').fill('LTAI5traffic')
  await page.getByLabel('流量额度').fill('350')
  await page.getByRole('button', { name: '完成安装' }).click()
  await expect(page.getByRole('heading', { name: '资源控制台' })).toBeVisible({ timeout: 30_000 })
  expect(maxTraffic).toBe(350)
})

test('setup posts custom region_id', async ({ page }) => {
  await mockInitStatus(page, false)
  let regionId = ''
  await page.route('**/api/v1/setup', async (route) => {
    const body = JSON.parse(route.request().postData() || '{}') as { accounts?: { region_id?: string }[] }
    regionId = body.accounts?.[0]?.region_id || ''
    expectKnownKeys(body, CONFIG_OBJECT_KEYS)
    if (body.accounts?.[0]) expectKnownKeys(body.accounts[0], ACCOUNT_OBJECT_KEYS)
    await route.fulfill({ status: 201, json: { success: true, csrf_token: 'test-csrf' } })
  })
  await mockDashboardReads(page)

  await page.goto('/')
  const passwords = page.locator('input[type="password"]')
  await passwords.nth(0).fill(TEST_PASSWORD)
  await passwords.nth(1).fill(TEST_PASSWORD)
  await page.getByRole('button', { name: '继续' }).click()
  await page.getByRole('button', { name: '继续' }).click()
  await page.getByLabel('AccessKey ID').fill('LTAI5region')
  await page.getByRole('combobox', { name: '地域' }).click()
  await page.getByRole('combobox', { name: '地域' }).fill('zhangjiakou')
  await page.getByRole('option', { name: /华北 3（张家口）.*cn-zhangjiakou/ }).click()
  await page.getByRole('button', { name: '完成安装' }).click()
  await expect(page.getByRole('heading', { name: '资源控制台' })).toBeVisible({ timeout: 30_000 })
  expect(regionId).toBe('cn-zhangjiakou')
})

test('refresh-all surfaces the csrf_failed envelope after login', async ({ page }) => {
  await mockInitStatus(page, true)
  let authed = false
  await page.route('**/api/v1/auth/login', async (route) => {
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
  await page.route('**/api/v1/accounts/refresh', (route) => route.fulfill({
    status: 403,
    json: { error: { code: 'csrf_failed', message: 'CSRF 校验失败' } },
  }))

  await page.goto('/')
  await page.getByLabel('管理员密码').fill(TEST_PASSWORD)
  await page.getByRole('button', { name: '安全登录' }).click()
  await expect(page.getByRole('heading', { name: '资源控制台' })).toBeVisible({ timeout: 30_000 })
  await page.getByRole('button', { name: '强制刷新全部实例' }).click()
  await expect(page.getByText('CSRF 校验失败')).toBeVisible()
  await expect(page.getByRole('heading', { name: '资源控制台' })).toBeVisible()
})


test('setup posts schedule window', async ({ page }) => {
  await mockInitStatus(page, false)
  let account: { schedule_enabled?: boolean; start_time?: string; stop_time?: string } | undefined
  await page.route('**/api/v1/setup', async (route) => {
    const body = JSON.parse(route.request().postData() || '{}') as { accounts?: typeof account[] }
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
  await page.getByLabel('AccessKey ID').fill('LTAI5sched')
  await page.getByText('每日定时开关机', { exact: true }).click()
  await page.getByLabel('开机时间').fill('09:00')
  await page.getByLabel('关机时间').fill('22:00')
  await page.getByRole('button', { name: '完成安装' }).click()
  await expect(page.getByRole('heading', { name: '资源控制台' })).toBeVisible({ timeout: 30_000 })
  expect(account).toMatchObject({ schedule_enabled: true, start_time: '09:00', stop_time: '22:00' })
})


test('setup posts account remark instance id and secret', async ({ page }) => {
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
  await page.getByLabel('AccessKey ID').fill('LTAI5remark')
  await page.getByLabel('AccessKey Secret').fill('fixture-secret-not-real')
  await page.getByLabel('实例 ID').fill('i-bp-fixture')
  await page.getByLabel('备注').fill('香港主节点')
  await page.getByRole('button', { name: '完成安装' }).click()
  await expect(page.getByRole('heading', { name: '资源控制台' })).toBeVisible({ timeout: 30_000 })
  expect(account).toMatchObject({
    access_key_id: 'LTAI5remark',
    access_key_secret: 'fixture-secret-not-real',
    instance_id: 'i-bp-fixture',
    remark: '香港主节点',
  })
})


test('init-status failure surfaces the live init_status_failed envelope', async ({ page }) => {
  await page.route('**/api/v1/system/init-status', (route) => route.fulfill({
    status: 500,
    json: { error: { code: 'init_status_failed', message: '无法读取初始化状态' } },
  }))

  await page.goto('/')
  await expect(page.getByRole('heading', { name: '控制台暂时不可用' })).toBeVisible()
  await expect(page.getByText('无法读取初始化状态')).toBeVisible()
})

test('login failure surfaces the live login_failed envelope', async ({ page }) => {
  await mockInitStatus(page, true)
  await mockUnauthorizedSession(page)
  await page.route('**/api/v1/auth/login', (route) => route.fulfill({
    status: 500,
    json: { error: { code: 'login_failed', message: '登录失败' } },
  }))

  await page.goto('/')
  await page.getByLabel('管理员密码').fill(TEST_PASSWORD)
  await page.getByRole('button', { name: '安全登录' }).click()
  await expect(page.getByText('登录失败')).toBeVisible()
  await expect(page.getByRole('heading', { name: '欢迎回来' })).toBeVisible()
})


test('keep-alive disables stop without posting an action', async ({ page }) => {
  let stopCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page, dashboardStatus, { ...dashboardConfig, keep_alive: true })
  await page.route('**/api/v1/accounts/**/actions/stop', (route) => {
    stopCalls += 1
    return route.fulfill({ status: 202, json: { id: 'stop-1', status: 'queued' } })
  })

  await page.goto('/')
  await expect(page.getByRole('heading', { name: '资源控制台' })).toBeVisible()
  await expect(page.getByRole('button', { name: '保活启用，不能关机' })).toBeDisabled()
  expect(stopCalls).toBe(0)
})


test('dashboard shows live billing_error on the account card', async ({ page }) => {
  await mockInitStatus(page, true)
  await mockDashboardReads(page, {
    ...dashboardStatus,
    accounts: [{ ...dashboardAccount, billing_error: '账单查询失败' }],
  }, { ...dashboardConfig, enable_billing: true })

  await page.goto('/')
  const billing = page.locator('.account-billing')
  await expect(billing).toBeVisible()
  await expect(billing.locator('.billing-error')).toHaveText('账单查询失败')
  await expect(billing.getByText('已同步')).toHaveCount(0)
})


test('dashboard marks over_threshold and stale from the status contract', async ({ page }) => {
  await mockInitStatus(page, true)
  await mockDashboardReads(page, {
    ...dashboardStatus,
    accounts: [{ ...dashboardAccount, over_threshold: true, stale: true, percentage: 98 }],
  })

  await page.goto('/')
  await expect(page.getByRole('heading', { name: '资源控制台' })).toBeVisible()
  await expect(page.locator('.account-card.account-card--alert')).toBeVisible()
  await expect(page.locator('.account-card__footer .stale')).toBeVisible()
  await expect(page.locator('.metric--amber')).toContainText('1')
})


test('Stopped instance posts start and Starting has no power controls', async ({ page }) => {
  let startCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page, {
    ...dashboardStatus,
    accounts: [
      { ...dashboardAccount, id: 1, remark: '停止节点', instance_status: 'Stopped' },
      { ...dashboardAccount, id: 2, remark: '启动节点', instance_status: 'Starting' },
    ],
  })
  await page.route('**/api/v1/accounts/1/actions/start', (route) => {
    startCalls += 1
    expect(route.request().method()).toBe('POST')
    return route.fulfill({ status: 202, json: jobFixture('start-1', 'queued', 1) })
  })
  await page.route('**/api/v1/jobs/**', (route) => {
    const id = route.request().url().split('/').pop() || 'start-1'
    return route.fulfill({ json: jobFixture(id, 'completed', 1) })
  })

  await page.goto('/')
  await expect(page.getByText('已停止')).toBeVisible()
  await expect(page.getByText('启动中')).toBeVisible()
  await expect(page.getByRole('button', { name: '开机' })).toHaveCount(1)
  await expect(page.getByRole('button', { name: '关机' })).toHaveCount(0)
  await page.getByRole('button', { name: '开机' }).click()
  await expect(page.getByText('已发送开机指令')).toBeVisible()
  expect(startCalls).toBe(1)
})


test('refresh-all surfaces the enqueue_failed envelope after login', async ({ page }) => {
  await mockInitStatus(page, true)
  let authed = false
  await page.route('**/api/v1/auth/login', async (route) => {
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
  await page.route('**/api/v1/accounts/refresh', (route) => route.fulfill({
    status: 500,
    json: { error: { code: 'enqueue_failed', message: '任务提交失败' } },
  }))

  await page.goto('/')
  await page.getByLabel('管理员密码').fill(TEST_PASSWORD)
  await page.getByRole('button', { name: '安全登录' }).click()
  await expect(page.getByRole('heading', { name: '资源控制台' })).toBeVisible({ timeout: 30_000 })
  await page.getByRole('button', { name: '强制刷新全部实例' }).click()
  await expect(page.getByText('任务提交失败')).toBeVisible()
  await expect(page.getByRole('heading', { name: '资源控制台' })).toBeVisible()
})


test('failed start job surfaces the live job error', async ({ page }) => {
  await mockInitStatus(page, true)
  await mockDashboardReads(page, {
    ...dashboardStatus,
    accounts: [{ ...dashboardAccount, instance_status: 'Stopped' }],
  })
  await page.route('**/api/v1/accounts/1/actions/start', (route) => {
    expect(route.request().method()).toBe('POST')
    return route.fulfill({ status: 202, json: jobFixture('start-fail', 'queued', 1) })
  })
  await page.route('**/api/v1/jobs/**', (route) => {
    const failed = jobFixture('start-fail', 'failed', 1)
    failed.error = '开机失败'
    return route.fulfill({ json: failed })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '开机' }).click()
  await expect(page.getByText('开机失败')).toBeVisible()
})

test('instance refresh surfaces the job_not_found envelope after login', async ({ page }) => {
  await mockInitStatus(page, true)
  let authed = false
  await page.route('**/api/v1/auth/login', async (route) => {
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
  await page.route('**/api/v1/accounts/1/refresh', (route) => {
    expect(route.request().method()).toBe('POST')
    return route.fulfill({ status: 202, json: jobFixture('missing-job', 'queued') })
  })
  await page.route('**/api/v1/jobs/**', (route) => route.fulfill({
    status: 404,
    json: { error: { code: 'job_not_found', message: '任务不存在' } },
  }))

  await page.goto('/')
  await page.getByLabel('管理员密码').fill(TEST_PASSWORD)
  await page.getByRole('button', { name: '安全登录' }).click()
  await expect(page.getByRole('heading', { name: '资源控制台' })).toBeVisible({ timeout: 30_000 })
  await page.getByRole('button', { name: '刷新实例' }).click()
  await expect(page.getByText('任务不存在')).toBeVisible()
  await expect(page.getByRole('heading', { name: '资源控制台' })).toBeVisible()
})


test('Running instance posts stop when keep_alive is off', async ({ page }) => {
  let stopCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page, dashboardStatus, { ...dashboardConfig, keep_alive: false })
  await page.route('**/api/v1/accounts/1/actions/stop', (route) => {
    stopCalls += 1
    expect(route.request().method()).toBe('POST')
    return route.fulfill({ status: 202, json: jobFixture('stop-1', 'queued', 1) })
  })
  await page.route('**/api/v1/jobs/**', (route) => {
    const id = route.request().url().split('/').pop() || 'stop-1'
    return route.fulfill({ json: jobFixture(id, 'completed', 1) })
  })

  await page.goto('/')
  await expect(page.getByRole('button', { name: '关机' })).toBeEnabled()
  await page.getByRole('button', { name: '关机' }).click()
  await expect(page.getByText('已发送关机指令')).toBeVisible()
  expect(stopCalls).toBe(1)
})

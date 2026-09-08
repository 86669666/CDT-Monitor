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

test('login surfaces the status_failed envelope when dashboard load fails', async ({ page }) => {
  await mockInitStatus(page, true)
  let authed = false
  await page.route('**/api/v1/auth/login', async (route) => {
    authed = true
    await route.fulfill({ json: { success: true, csrf_token: 'test-csrf' } })
  })
  await page.route('**/api/v1/status', (route) => {
    if (!authed) return route.fulfill({ status: 401, json: { error: { code: 'unauthorized', message: '请登录或提供有效 API Key' } } })
    return route.fulfill({ status: 500, json: { error: { code: 'status_failed', message: '状态加载失败' } } })
  })
  await page.route('**/api/v1/config', (route) => {
    if (!authed) return route.fulfill({ status: 401, json: { error: { code: 'unauthorized', message: '请登录或提供有效 API Key' } } })
    return route.fulfill({ json: dashboardConfig })
  })

  await page.goto('/')
  await page.getByLabel('管理员密码').fill(TEST_PASSWORD)
  await page.getByRole('button', { name: '安全登录' }).click()
  await expect(page.getByText('状态加载失败')).toBeVisible()
  await expect(page.getByRole('heading', { name: '欢迎回来' })).toBeVisible()
})


test('login surfaces the config_failed envelope when dashboard load fails', async ({ page }) => {
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
    return route.fulfill({ status: 500, json: { error: { code: 'config_failed', message: '配置加载失败' } } })
  })

  await page.goto('/')
  await page.getByLabel('管理员密码').fill(TEST_PASSWORD)
  await page.getByRole('button', { name: '安全登录' }).click()
  await expect(page.getByText('配置加载失败')).toBeVisible()
  await expect(page.getByRole('heading', { name: '欢迎回来' })).toBeVisible()
})

test('single instance refresh completes from the live job contract', async ({ page }) => {
  let refreshCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/accounts/1/refresh', (route) => {
    refreshCalls += 1
    expect(route.request().method()).toBe('POST')
    return route.fulfill({ status: 202, json: jobFixture('refresh-one', 'queued', 1) })
  })
  await page.route('**/api/v1/jobs/**', (route) => {
    const id = route.request().url().split('/').pop() || 'refresh-one'
    return route.fulfill({ json: jobFixture(id, 'completed', 1) })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '刷新实例' }).click()
  await expect(page.getByText('实例状态已刷新')).toBeVisible()
  expect(refreshCalls).toBe(1)
})



test('logout posts the live auth contract and returns to login', async ({ page }) => {
  let logoutCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/auth/logout', (route) => {
    logoutCalls += 1
    expect(route.request().method()).toBe('POST')
    return route.fulfill({ json: { success: true } })
  })

  await page.goto('/')
  await expect(page.getByRole('heading', { name: '资源控制台' })).toBeVisible()
  await page.getByRole('button', { name: '退出' }).click()
  await expect(page.getByRole('heading', { name: '欢迎回来' })).toBeVisible()
  expect(logoutCalls).toBe(1)
})

test('login surfaces the session_failed envelope', async ({ page }) => {
  await mockInitStatus(page, true)
  await mockUnauthorizedSession(page)
  await page.route('**/api/v1/auth/login', (route) => route.fulfill({
    status: 500,
    json: { error: { code: 'session_failed', message: '无法创建会话' } },
  }))

  await page.goto('/')
  await page.getByLabel('管理员密码').fill(TEST_PASSWORD)
  await page.getByRole('button', { name: '安全登录' }).click()
  await expect(page.getByText('无法创建会话')).toBeVisible()
  await expect(page.getByRole('heading', { name: '欢迎回来' })).toBeVisible()
})


test('login surfaces the invalid_request envelope', async ({ page }) => {
  await mockInitStatus(page, true)
  await mockUnauthorizedSession(page)
  await page.route('**/api/v1/auth/login', (route) => route.fulfill({
    status: 400,
    json: { error: { code: 'invalid_request', message: 'json: unknown field "nope"' } },
  }))

  await page.goto('/')
  await page.getByLabel('管理员密码').fill(TEST_PASSWORD)
  await page.getByRole('button', { name: '安全登录' }).click()
  await expect(page.getByText('json: unknown field "nope"')).toBeVisible()
  await expect(page.getByRole('heading', { name: '欢迎回来' })).toBeVisible()
})

test('admin password update surfaces the invalid_password envelope', async ({ page }) => {
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/admin/passkeys', (route) => route.fulfill({ json: { passkeys: [] } }))
  await page.route('**/api/v1/admin/password', (route) => {
    expect(route.request().method()).toBe('PUT')
    expect(JSON.parse(route.request().postData() || '{}')).toEqual({
      current_password: TEST_PASSWORD,
      new_password: 'short',
    })
    return route.fulfill({
      status: 400,
      json: { error: { code: 'invalid_password', message: '新密码至少需要 10 个字符' } },
    })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '管理员' }).click()
  await page.getByLabel('当前密码').fill(TEST_PASSWORD)
  await page.getByLabel('新密码', { exact: true }).fill('short')
  await page.getByLabel('确认新密码').fill('short')
  await page.getByRole('button', { name: '保存新密码' }).click()
  await expect(page.getByText('新密码至少需要 10 个字符')).toBeVisible()
  await expect(page.getByRole('heading', { name: '管理员设置' })).toBeVisible()
})

test('dashboard billing uses the live USD currency field', async ({ page }) => {
  await mockInitStatus(page, true)
  await mockDashboardReads(page, {
    ...dashboardStatus,
    accounts: [{ ...dashboardAccount, currency: 'USD' }],
  }, { ...dashboardConfig, enable_billing: true })

  await page.goto('/')
  const billing = page.locator('.account-billing')
  await expect(billing.getByText('$23.46')).toBeVisible()
  await expect(billing.getByText('$123.45')).toBeVisible()
  await expect(billing.getByText('¥')).toHaveCount(0)
})



test('empty dashboard opens settings from the zero-account state', async ({ page }) => {
  await mockInitStatus(page, true)
  await mockDashboardReads(page, { accounts: [], system_last_run: new Date().toISOString() }, { ...dashboardConfig, accounts: [] })
  await page.route('**/api/v1/api-keys', (route) => route.fulfill({ json: { keys: [] } }))
  await page.route('**/api/v1/logs**', (route) => route.fulfill({ json: { logs: [] } }))
  await page.route('**/api/v1/system/info**', (route) => route.fulfill({ json: {
    version: 'v2.0.1', commit: 'test', built_at: 'unknown',
    repository: 'https://github.com/wang4386/CDT-Monitor',
    release_url: 'https://github.com/wang4386/CDT-Monitor/releases',
  } }))

  await page.goto('/')
  await expect(page.getByRole('heading', { name: '添加第一个云端实例' })).toBeVisible()
  await expect(page.locator('.metric--blue')).toContainText('0')
  await page.getByRole('heading', { name: '添加第一个云端实例' }).click()
  await expect(page.getByRole('heading', { name: '控制台设置' })).toBeVisible()
})

test('admin password update surfaces invalid_credentials for the current password', async ({ page }) => {
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/admin/passkeys', (route) => route.fulfill({ json: { passkeys: [] } }))
  await page.route('**/api/v1/admin/password', (route) => {
    expect(route.request().method()).toBe('PUT')
    expect(JSON.parse(route.request().postData() || '{}')).toEqual({
      current_password: 'wrong-current-password',
      new_password: TEST_PASSWORD,
    })
    return route.fulfill({
      status: 401,
      json: { error: { code: 'invalid_credentials', message: '当前密码错误' } },
    })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '管理员' }).click()
  await page.getByLabel('当前密码').fill('wrong-current-password')
  await page.getByLabel('新密码', { exact: true }).fill(TEST_PASSWORD)
  await page.getByLabel('确认新密码').fill(TEST_PASSWORD)
  await page.getByRole('button', { name: '保存新密码' }).click()
  await expect(page.getByText('当前密码错误')).toBeVisible()
  await expect(page.getByRole('heading', { name: '管理员设置' })).toBeVisible()
})


test('Pending instance shows waiting status without power controls', async ({ page }) => {
  await mockInitStatus(page, true)
  await mockDashboardReads(page, {
    ...dashboardStatus,
    accounts: [{ ...dashboardAccount, instance_status: 'Pending' }],
  })

  await page.goto('/')
  await expect(page.getByText('等待中')).toBeVisible()
  await expect(page.locator('.status-pill.warning')).toBeVisible()
  await expect(page.getByRole('button', { name: '开机' })).toHaveCount(0)
  await expect(page.getByRole('button', { name: '关机' })).toHaveCount(0)
  await expect(page.getByRole('button', { name: '刷新实例' })).toBeVisible()
})

test('admin password update surfaces the password_update_failed envelope', async ({ page }) => {
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/admin/passkeys', (route) => route.fulfill({ json: { passkeys: [] } }))
  await page.route('**/api/v1/admin/password', (route) => {
    expect(route.request().method()).toBe('PUT')
    expect(JSON.parse(route.request().postData() || '{}')).toEqual({
      current_password: TEST_PASSWORD,
      new_password: 'Rotated-Password-42!',
    })
    return route.fulfill({
      status: 500,
      json: { error: { code: 'password_update_failed', message: '管理员密码更新失败' } },
    })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '管理员' }).click()
  await page.getByLabel('当前密码').fill(TEST_PASSWORD)
  await page.getByLabel('新密码', { exact: true }).fill('Rotated-Password-42!')
  await page.getByLabel('确认新密码').fill('Rotated-Password-42!')
  await page.getByRole('button', { name: '保存新密码' }).click()
  await expect(page.getByText('管理员密码更新失败')).toBeVisible()
  await expect(page.getByRole('heading', { name: '管理员设置' })).toBeVisible()
})

test('admin password update posts the live success contract', async ({ page }) => {
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/admin/passkeys', (route) => route.fulfill({ json: { passkeys: [] } }))
  await page.route('**/api/v1/admin/password', (route) => {
    expect(route.request().method()).toBe('PUT')
    expect(JSON.parse(route.request().postData() || '{}')).toEqual({
      current_password: TEST_PASSWORD,
      new_password: 'Rotated-Password-42!',
    })
    return route.fulfill({ json: { success: true } })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '管理员' }).click()
  await page.getByLabel('当前密码').fill(TEST_PASSWORD)
  await page.getByLabel('新密码', { exact: true }).fill('Rotated-Password-42!')
  await page.getByLabel('确认新密码').fill('Rotated-Password-42!')
  await page.getByRole('button', { name: '保存新密码' }).click()
  await expect(page.getByText('管理员密码已更新')).toBeVisible()
  await expect(page.getByLabel('当前密码')).toHaveValue('')
  await expect(page.getByLabel('新密码', { exact: true })).toHaveValue('')
  await expect(page.getByLabel('确认新密码')).toHaveValue('')
})

test('Stopping and Unknown instance statuses hide power controls', async ({ page }) => {
  await mockInitStatus(page, true)
  await mockDashboardReads(page, {
    ...dashboardStatus,
    accounts: [
      { ...dashboardAccount, id: 1, remark: '停止中节点', instance_status: 'Stopping' },
      { ...dashboardAccount, id: 2, remark: '未知节点', instance_status: 'Unknown' },
    ],
  })

  await page.goto('/')
  await expect(page.locator('.status-pill').getByText('停止中', { exact: true })).toBeVisible()
  await expect(page.locator('.status-pill').getByText('未知', { exact: true })).toBeVisible()
  await expect(page.locator('.status-pill.warning')).toBeVisible()
  await expect(page.locator('.status-pill.neutral')).toBeVisible()
  await expect(page.getByRole('button', { name: '开机' })).toHaveCount(0)
  await expect(page.getByRole('button', { name: '关机' })).toHaveCount(0)
  await expect(page.getByRole('button', { name: '刷新实例' })).toHaveCount(2)
})


test('admin password update rejects mismatched confirmation without a network call', async ({ page }) => {
  let passwordCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/admin/passkeys', (route) => route.fulfill({ json: { passkeys: [] } }))
  await page.route('**/api/v1/admin/password', (route) => {
    passwordCalls += 1
    return route.fulfill({ json: { success: true } })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '管理员' }).click()
  await page.getByLabel('当前密码').fill(TEST_PASSWORD)
  await page.getByLabel('新密码', { exact: true }).fill('Rotated-Password-42!')
  await page.getByLabel('确认新密码').fill('Different-Password-42!')
  await page.getByRole('button', { name: '保存新密码' }).click()
  await expect(page.getByText('两次新密码不一致')).toBeVisible()
  expect(passwordCalls).toBe(0)
})

test('dashboard shows never-run status from empty last_updated fields', async ({ page }) => {
  await mockInitStatus(page, true)
  await mockDashboardReads(page, {
    accounts: [{ ...dashboardAccount, last_updated: '' }],
    system_last_run: '',
  })

  await page.goto('/')
  await expect(page.locator('.overview-time b')).toHaveText('尚未运行')
  await expect(page.locator('.account-card__footer')).toContainText('等待首次同步')
  await expect(page.locator('.heartbeat')).toContainText('监控任务延迟')
})



test('settings email test posts the live notification job contract', async ({ page }) => {
  let testCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/notifications/test/email', (route) => {
    testCalls += 1
    expect(route.request().method()).toBe('POST')
    const job = jobFixture('notify-email', 'queued')
    job.type = 'test_notification'
    return route.fulfill({ status: 202, json: job })
  })
  await page.route('**/api/v1/jobs/**', (route) => {
    const id = route.request().url().split('/').pop() || 'notify-email'
    const job = jobFixture(id, 'completed')
    job.type = 'test_notification'
    return route.fulfill({ json: job })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: '发送测试' }).click()
  await expect(page.getByText('测试通知已送达')).toBeVisible()
  expect(testCalls).toBe(1)
})

test('settings logs surface the logs_failed envelope', async ({ page }) => {
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/logs**', (route) => route.fulfill({
    status: 500,
    json: { error: { code: 'logs_failed', message: '日志操作失败' } },
  }))

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '日志' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '日志操作失败' }).first()).toBeVisible()
  await expect(page.getByText('暂无日志')).toBeVisible()
  await expect(page.getByRole('heading', { name: '运行日志' })).toBeVisible()
})


test('log clear surfaces the logs_failed envelope', async ({ page }) => {
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/logs**', (route) => {
    if (route.request().method() === 'DELETE') {
      return route.fulfill({
        status: 500,
        json: { error: { code: 'logs_failed', message: '日志操作失败' } },
      })
    }
    return route.fulfill({ json: { logs: [{ id: 1, type: 'audit', message: '保留日志', created_at: new Date().toISOString() }] } })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '日志' }).click()
  await expect(page.getByText('保留日志')).toBeVisible()
  await page.getByRole('button', { name: '清空' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '日志操作失败' }).first()).toBeVisible()
  await expect(page.getByText('保留日志')).toBeVisible()
})

test('settings telegram test posts the live notification job contract', async ({ page }) => {
  let testCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/notifications/test/telegram', (route) => {
    testCalls += 1
    expect(route.request().method()).toBe('POST')
    const job = jobFixture('notify-telegram', 'queued')
    job.type = 'test_notification'
    return route.fulfill({ status: 202, json: job })
  })
  await page.route('**/api/v1/jobs/**', (route) => {
    const id = route.request().url().split('/').pop() || 'notify-telegram'
    const job = jobFixture(id, 'completed')
    job.type = 'test_notification'
    return route.fulfill({ json: job })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: 'Telegram' }).click()
  await page.getByRole('button', { name: '发送测试' }).click()
  await expect(page.getByText('测试通知已送达')).toBeVisible()
  expect(testCalls).toBe(1)
})


test('settings webhook test posts the live notification job contract', async ({ page }) => {
  let testCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/notifications/test/webhook', (route) => {
    testCalls += 1
    expect(route.request().method()).toBe('POST')
    const job = jobFixture('notify-webhook', 'queued')
    job.type = 'test_notification'
    return route.fulfill({ status: 202, json: job })
  })
  await page.route('**/api/v1/jobs/**', (route) => {
    const id = route.request().url().split('/').pop() || 'notify-webhook'
    const job = jobFixture(id, 'completed')
    job.type = 'test_notification'
    return route.fulfill({ json: job })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: 'Webhook' }).click()
  await page.getByRole('button', { name: '发送测试' }).click()
  await expect(page.getByText('测试通知已送达')).toBeVisible()
  expect(testCalls).toBe(1)
})

test('settings webhook test surfaces the enqueue_failed envelope', async ({ page }) => {
  let testCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/notifications/test/webhook', (route) => {
    testCalls += 1
    expect(route.request().method()).toBe('POST')
    return route.fulfill({
      status: 500,
      json: { error: { code: 'enqueue_failed', message: '任务提交失败' } },
    })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: 'Webhook' }).click()
  await page.getByRole('button', { name: '发送测试' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '任务提交失败' }).first()).toBeVisible()
  expect(testCalls).toBe(1)
})

test('settings webhook test surfaces a failed notification job', async ({ page }) => {
  let testCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/notifications/test/webhook', (route) => {
    testCalls += 1
    expect(route.request().method()).toBe('POST')
    const job = jobFixture('notify-webhook-fail', 'queued')
    job.type = 'test_notification'
    return route.fulfill({ status: 202, json: job })
  })
  await page.route('**/api/v1/jobs/**', (route) => {
    const failed = jobFixture('notify-webhook-fail', 'failed')
    failed.type = 'test_notification'
    failed.error = 'webhook HTTP 502: bad gateway'
    return route.fulfill({ json: failed })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: 'Webhook' }).click()
  await page.getByRole('button', { name: '发送测试' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: 'webhook HTTP 502: bad gateway' }).first()).toBeVisible()
  expect(testCalls).toBe(1)
})

test('settings API key create posts the live key contract', async ({ page }) => {
  const created = {
    id: 3,
    name: '桌面小组件',
    scopes: ['widget:read'],
    created_at: new Date().toISOString(),
  }
  const token = 'cdt_test_token_once'
  let createCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/api-keys', async (route) => {
    if (route.request().method() === 'POST') {
      createCalls += 1
      expect(JSON.parse(route.request().postData() || '{}')).toEqual({
        name: '桌面小组件',
        scopes: ['widget:read'],
      })
      return route.fulfill({ status: 201, json: { key: created, token } })
    }
    return route.fulfill({ json: { keys: createCalls > 0 ? [created] : [] } })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: 'API Key' }).click()
  await page.getByRole('button', { name: '创建 Key' }).click()
  await expect(page.getByText('仅显示一次')).toBeVisible()
  await expect(page.locator('code')).toHaveText(token)
  await expect(page.locator('.key-row')).toContainText('桌面小组件')
  await expect(page.locator('.key-row')).toContainText('widget:read')
  expect(createCalls).toBe(1)
})

test('settings API keys surface the api_keys_failed envelope', async ({ page }) => {
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/api-keys', (route) => route.fulfill({
    status: 500,
    json: { error: { code: 'api_keys_failed', message: 'API Key 列表加载失败' } },
  }))

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: 'API Key' }).click()
  await expect(page.locator('.inline-error')).toContainText('API Key 列表加载失败')
  await expect(page.getByRole('button', { name: '重试' })).toBeVisible()
})

test('settings API key revoke posts the live success contract', async ({ page }) => {
  const existing = {
    id: 4,
    name: '桌面小组件',
    scopes: ['widget:read'],
    created_at: new Date().toISOString(),
  }
  let revokeCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/api-keys', (route) => {
    return route.fulfill({ json: { keys: revokeCalls > 0 ? [] : [existing] } })
  })
  await page.route('**/api/v1/api-keys/**', (route) => {
    expect(route.request().method()).toBe('DELETE')
    expect(route.request().url()).toMatch(/\/api\/v1\/api-keys\/4$/)
    revokeCalls += 1
    return route.fulfill({ json: { success: true } })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: 'API Key' }).click()
  await expect(page.locator('.key-row')).toContainText('桌面小组件')
  await page.getByRole('button', { name: '撤销' }).click()
  await expect(page.getByText('API Key 已撤销')).toBeVisible()
  await expect(page.locator('.key-row')).toHaveCount(0)
  expect(revokeCalls).toBe(1)
})

test('settings API key create surfaces the api_key_failed envelope', async ({ page }) => {
  let createCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/api-keys', (route) => {
    if (route.request().method() === 'POST') {
      createCalls += 1
      return route.fulfill({
        status: 400,
        json: { error: { code: 'api_key_failed', message: '无法创建 API Key' } },
      })
    }
    return route.fulfill({ json: { keys: [] } })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: 'API Key' }).click()
  await page.getByRole('button', { name: '创建 Key' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '无法创建 API Key' }).first()).toBeVisible()
  await expect(page.getByText('仅显示一次')).toHaveCount(0)
  expect(createCalls).toBe(1)
})

test('settings save posts the live config contract', async ({ page }) => {
  let saveCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/config', async (route) => {
    if (route.request().method() === 'PUT') {
      saveCalls += 1
      const body = JSON.parse(route.request().postData() || '{}') as Record<string, unknown>
      expectKnownKeys(body, CONFIG_OBJECT_KEYS)
      expect(body.enable_schedule_notification).toBe(true)
      return route.fulfill({ json: { success: true } })
    }
    return route.fulfill({ json: dashboardConfig })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByText('定时任务通知', { exact: true }).click()
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.getByText('配置已安全保存')).toBeVisible()
  expect(saveCalls).toBe(1)
})

test('settings save surfaces the config_failed envelope', async ({ page }) => {
  let saveCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/config', (route) => {
    if (route.request().method() === 'PUT') {
      saveCalls += 1
      return route.fulfill({
        status: 400,
        json: { error: { code: 'config_failed', message: '配置保存失败' } },
      })
    }
    return route.fulfill({ json: dashboardConfig })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '配置保存失败' }).first()).toBeVisible()
  expect(saveCalls).toBe(1)
})

test('settings bark webhook template posts the live webhook contract', async ({ page }) => {
  let savedWebhook: Record<string, unknown> | undefined
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/config', async (route) => {
    if (route.request().method() === 'PUT') {
      const body = JSON.parse(route.request().postData() || '{}') as { notifications?: { webhook?: Record<string, unknown> } }
      expectKnownKeys(body, CONFIG_OBJECT_KEYS)
      savedWebhook = body.notifications?.webhook
      return route.fulfill({ json: { success: true } })
    }
    return route.fulfill({ json: dashboardConfig })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: 'Webhook' }).click()
  await page.locator('#webhook-template').click()
  await page.getByRole('option', { name: 'Bark' }).click()
  await page.getByLabel('Bark Key').fill('test-key')
  await page.getByRole('button', { name: '生成 Webhook' }).click()
  await expect(page.getByText('Bark 模板已生成，请检查后保存')).toBeVisible()
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.getByText('配置已安全保存')).toBeVisible()
  expect(savedWebhook).toMatchObject({
    enabled: true,
    provider: 'bark',
    method: 'GET',
    request_type: 'JSON',
    headers: '',
    url: 'https://api.day.app/test-key/#TITLE#/#MSG#',
    body: '',
    secret: '',
    secret_configured: false,
  })
})

test('instance refresh surfaces the job_failed envelope', async ({ page }) => {
  let refreshCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/accounts/1/refresh', (route) => {
    refreshCalls += 1
    expect(route.request().method()).toBe('POST')
    return route.fulfill({ status: 202, json: jobFixture('refresh-fail', 'queued', 1) })
  })
  await page.route('**/api/v1/jobs/**', (route) => route.fulfill({
    status: 500,
    json: { error: { code: 'job_failed', message: '任务查询失败' } },
  }))

  await page.goto('/')
  await page.getByRole('button', { name: '刷新实例' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '任务查询失败' }).first()).toBeVisible()
  expect(refreshCalls).toBe(1)
})

test('settings API key create posts all live scopes', async ({ page }) => {
  const created = {
    id: 5,
    name: '桌面小组件',
    scopes: ['widget:read', 'instance:control', 'cron:run'],
    created_at: new Date().toISOString(),
  }
  let createCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/api-keys', async (route) => {
    if (route.request().method() === 'POST') {
      createCalls += 1
      expect(JSON.parse(route.request().postData() || '{}')).toEqual({
        name: '桌面小组件',
        scopes: ['widget:read', 'instance:control', 'cron:run'],
      })
      return route.fulfill({ status: 201, json: { key: created, token: 'cdt_scoped_token' } })
    }
    return route.fulfill({ json: { keys: createCalls > 0 ? [created] : [] } })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: 'API Key' }).click()
  await page.getByText('控制实例', { exact: true }).click()
  await page.getByText('触发任务', { exact: true }).click()
  await page.getByRole('button', { name: '创建 Key' }).click()
  await expect(page.getByText('仅显示一次')).toBeVisible()
  await expect(page.locator('.key-row')).toContainText('widget:read · instance:control · cron:run')
  expect(createCalls).toBe(1)
})

test('admin passkeys surface the passkeys_failed envelope', async ({ page }) => {
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/admin/passkeys', (route) => route.fulfill({
    status: 500,
    json: { error: { code: 'passkeys_failed', message: 'Passkey 列表加载失败' } },
  }))

  await page.goto('/')
  await page.getByRole('button', { name: '管理员' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: 'Passkey 列表加载失败' }).first()).toBeVisible()
  await expect(page.getByText('尚未创建 Passkey')).toBeVisible()
})

test('admin passkey delete posts the live success contract', async ({ page }) => {
  const existing = { id: 7, name: '办公室电脑', created_at: new Date().toISOString() }
  let deleteCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/admin/passkeys', (route) => {
    return route.fulfill({ json: { passkeys: deleteCalls > 0 ? [] : [existing] } })
  })
  await page.route('**/api/v1/admin/passkeys/**', (route) => {
    expect(route.request().method()).toBe('DELETE')
    expect(route.request().url()).toMatch(/\/api\/v1\/admin\/passkeys\/7$/)
    deleteCalls += 1
    return route.fulfill({ json: { success: true } })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '管理员' }).click()
  await expect(page.locator('.passkey-row')).toContainText('办公室电脑')
  await page.getByRole('button', { name: '删除 Passkey' }).click()
  await expect(page.getByText('Passkey 已删除')).toBeVisible()
  await expect(page.getByText('尚未创建 Passkey')).toBeVisible()
  expect(deleteCalls).toBe(1)
})

test('admin passkey delete surfaces the passkey_failed envelope', async ({ page }) => {
  const existing = { id: 8, name: '办公室电脑', created_at: new Date().toISOString() }
  let deleteCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/admin/passkeys', (route) => route.fulfill({ json: { passkeys: [existing] } }))
  await page.route('**/api/v1/admin/passkeys/**', (route) => {
    deleteCalls += 1
    expect(route.request().method()).toBe('DELETE')
    return route.fulfill({
      status: 500,
      json: { error: { code: 'passkey_failed', message: 'Passkey 删除失败' } },
    })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '管理员' }).click()
  await page.getByRole('button', { name: '删除 Passkey' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: 'Passkey 删除失败' }).first()).toBeVisible()
  await expect(page.locator('.passkey-row')).toContainText('办公室电脑')
  expect(deleteCalls).toBe(1)
})

test('settings billing enable starts account refresh', async ({ page }) => {
  const unloaded = { ...dashboardConfig, enable_billing: false }
  let saveCalls = 0
  let refreshCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page, dashboardStatus, unloaded)
  await page.route('**/api/v1/config', async (route) => {
    if (route.request().method() === 'PUT') {
      saveCalls += 1
      const body = JSON.parse(route.request().postData() || '{}') as Record<string, unknown>
      expectKnownKeys(body, CONFIG_OBJECT_KEYS)
      expect(body.enable_billing).toBe(true)
      return route.fulfill({ json: { success: true } })
    }
    return route.fulfill({ json: unloaded })
  })
  await page.route('**/api/v1/accounts/1/refresh', (route) => {
    refreshCalls += 1
    expect(route.request().method()).toBe('POST')
    return route.fulfill({ status: 202, json: jobFixture('billing-refresh', 'queued', 1) })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByText('账单与余额', { exact: true }).click()
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.getByText('配置已保存，账单同步已开始')).toBeVisible()
  expect(saveCalls).toBe(1)
  expect(refreshCalls).toBe(1)
})

test('settings billing enable keeps save when refresh enqueue fails', async ({ page }) => {
  const unloaded = { ...dashboardConfig, enable_billing: false }
  let saveCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page, dashboardStatus, unloaded)
  await page.route('**/api/v1/config', async (route) => {
    if (route.request().method() === 'PUT') {
      saveCalls += 1
      return route.fulfill({ json: { success: true } })
    }
    return route.fulfill({ json: unloaded })
  })
  await page.route('**/api/v1/accounts/1/refresh', (route) => route.fulfill({
    status: 500,
    json: { error: { code: 'enqueue_failed', message: '任务提交失败' } },
  }))

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByText('账单与余额', { exact: true }).click()
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.getByText('配置已保存，账单将在下次同步时更新')).toBeVisible()
  expect(saveCalls).toBe(1)
})

test('settings save surfaces the invalid_request envelope', async ({ page }) => {
  let saveCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/config', (route) => {
    if (route.request().method() === 'PUT') {
      saveCalls += 1
      return route.fulfill({
        status: 400,
        json: { error: { code: 'invalid_request', message: 'json: unknown field "nope"' } },
      })
    }
    return route.fulfill({ json: dashboardConfig })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: 'json: unknown field "nope"' }).first()).toBeVisible()
  expect(saveCalls).toBe(1)
})

test('settings dingtalk webhook template posts the live webhook contract', async ({ page }) => {
  let savedWebhook: Record<string, unknown> | undefined
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/config', async (route) => {
    if (route.request().method() === 'PUT') {
      const payload = JSON.parse(route.request().postData() || '{}') as { notifications?: { webhook?: Record<string, unknown> } }
      expectKnownKeys(payload, CONFIG_OBJECT_KEYS)
      savedWebhook = payload.notifications?.webhook
      return route.fulfill({ json: { success: true } })
    }
    return route.fulfill({ json: dashboardConfig })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: 'Webhook' }).click()
  await page.locator('#webhook-template').click()
  await page.getByRole('option', { name: '钉钉群机器人' }).click()
  await page.getByLabel('机器人 Access Token').fill('ding-token')
  await page.getByLabel('加签密钥（可选）').fill('SEC-test')
  await page.getByRole('button', { name: '生成 Webhook' }).click()
  await expect(page.getByText('钉钉群机器人 模板已生成，请检查后保存')).toBeVisible()
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.getByText('配置已安全保存')).toBeVisible()
  expect(savedWebhook).toMatchObject({
    enabled: true,
    provider: 'dingtalk',
    method: 'POST',
    request_type: 'JSON',
    headers: '',
    url: 'https://oapi.dingtalk.com/robot/send?access_token=ding-token',
    body: '{\n  "msgtype": "text",\n  "text": {\n    "content": "#MSG#"\n  }\n}',
    secret: 'SEC-test',
    secret_configured: false,
  })
})

test('settings wecom webhook template posts the live webhook contract', async ({ page }) => {
  let savedWebhook: Record<string, unknown> | undefined
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/config', async (route) => {
    if (route.request().method() === 'PUT') {
      const payload = JSON.parse(route.request().postData() || '{}') as { notifications?: { webhook?: Record<string, unknown> } }
      expectKnownKeys(payload, CONFIG_OBJECT_KEYS)
      savedWebhook = payload.notifications?.webhook
      return route.fulfill({ json: { success: true } })
    }
    return route.fulfill({ json: dashboardConfig })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: 'Webhook' }).click()
  await page.locator('#webhook-template').click()
  await page.getByRole('option', { name: '微信群机器人' }).click()
  await page.getByLabel('微信群机器人 Key').fill('wecom-key')
  await page.getByRole('button', { name: '生成 Webhook' }).click()
  await expect(page.getByText('微信群机器人 模板已生成，请检查后保存')).toBeVisible()
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.getByText('配置已安全保存')).toBeVisible()
  expect(savedWebhook).toMatchObject({
    enabled: true,
    provider: 'wecom',
    method: 'POST',
    request_type: 'JSON',
    headers: '',
    url: 'https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=wecom-key',
    body: '{\n  "msgtype": "text",\n  "text": {\n    "content": "#MSG#"\n  }\n}',
    secret: '',
    secret_configured: false,
  })
})

test('settings wxpusher webhook template posts the live webhook contract', async ({ page }) => {
  let savedWebhook: Record<string, unknown> | undefined
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/config', async (route) => {
    if (route.request().method() === 'PUT') {
      const payload = JSON.parse(route.request().postData() || '{}') as { notifications?: { webhook?: Record<string, unknown> } }
      expectKnownKeys(payload, CONFIG_OBJECT_KEYS)
      savedWebhook = payload.notifications?.webhook
      return route.fulfill({ json: { success: true } })
    }
    return route.fulfill({ json: dashboardConfig })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: 'Webhook' }).click()
  await page.locator('#webhook-template').click()
  await page.getByRole('option', { name: 'WxPusher' }).click()
  await page.getByLabel('AppToken').fill('AT_test')
  await page.getByLabel('UID').fill('UID_test')
  await page.getByRole('button', { name: '生成 Webhook' }).click()
  await expect(page.getByText('WxPusher 模板已生成，请检查后保存')).toBeVisible()
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.getByText('配置已安全保存')).toBeVisible()
  expect(savedWebhook).toMatchObject({
    enabled: true,
    provider: 'wxpusher',
    method: 'POST',
    request_type: 'JSON',
    headers: '',
    url: 'https://wxpusher.zjiecode.com/api/send/message',
    body: '{\n  "appToken": "AT_test",\n  "content": "#MSG#",\n  "summary": "#TITLE#",\n  "contentType": 1,\n  "uids": [\n    "UID_test"\n  ]\n}',
    secret: '',
    secret_configured: false,
  })
})

test('settings API key revoke surfaces the api_key_failed envelope', async ({ page }) => {
  const existing = {
    id: 9,
    name: '桌面小组件',
    scopes: ['widget:read'],
    created_at: new Date().toISOString(),
  }
  let revokeCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/api-keys', (route) => route.fulfill({ json: { keys: [existing] } }))
  await page.route('**/api/v1/api-keys/**', (route) => {
    revokeCalls += 1
    expect(route.request().method()).toBe('DELETE')
    return route.fulfill({
      status: 500,
      json: { error: { code: 'api_key_failed', message: '无法撤销 API Key' } },
    })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: 'API Key' }).click()
  await page.getByRole('button', { name: '撤销' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '无法撤销 API Key' }).first()).toBeVisible()
  await expect(page.locator('.key-row')).toContainText('桌面小组件')
  expect(revokeCalls).toBe(1)
})

test('log clear posts the live success contract', async ({ page }) => {
  let clearCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/logs**', (route) => {
    if (route.request().method() === 'DELETE') {
      expect(new URL(route.request().url()).searchParams.get('tab')).toBe('action')
      clearCalls += 1
      return route.fulfill({ json: { success: true } })
    }
    return route.fulfill({ json: { logs: clearCalls > 0 ? [] : [{ id: 1, type: 'audit', message: '待清空日志', created_at: new Date().toISOString() }] } })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '日志' }).click()
  await expect(page.getByText('待清空日志')).toBeVisible()
  await page.getByRole('button', { name: '清空' }).click()
  await expect(page.getByText('日志已清空')).toBeVisible()
  await expect(page.getByText('暂无日志')).toBeVisible()
  expect(clearCalls).toBe(1)
})

test('log heartbeat clear posts the live success contract', async ({ page }) => {
  let clearCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/logs**', (route) => {
    const tab = new URL(route.request().url()).searchParams.get('tab')
    if (route.request().method() === 'DELETE') {
      expect(tab).toBe('heartbeat')
      clearCalls += 1
      return route.fulfill({ json: { success: true } })
    }
    if (tab === 'heartbeat') {
      return route.fulfill({ json: { logs: clearCalls > 0 ? [] : [{ id: 2, type: 'heartbeat', message: '待清空心跳', created_at: new Date().toISOString() }] } })
    }
    return route.fulfill({ json: { logs: [{ id: 1, type: 'audit', message: '动作日志', created_at: new Date().toISOString() }] } })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '日志' }).click()
  await expect(page.getByText('动作日志')).toBeVisible()
  await page.getByRole('button', { name: '心跳' }).click()
  await expect(page.getByText('待清空心跳')).toBeVisible()
  await page.getByRole('button', { name: '清空' }).click()
  await expect(page.getByText('日志已清空')).toBeVisible()
  await expect(page.getByText('暂无日志')).toBeVisible()
  expect(clearCalls).toBe(1)
})

test('settings save sends the CSRF header from the cdt_csrf cookie', async ({ page }) => {
  const csrf = 'settings-csrf'
  let saveCsrf = ''
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/config', async (route) => {
    if (route.request().method() === 'PUT') {
      saveCsrf = route.request().headers()[CSRF_HEADER.toLowerCase()] || ''
      return route.fulfill({ json: { success: true } })
    }
    return route.fulfill({ json: dashboardConfig })
  })

  await page.goto('/')
  await page.context().addCookies([{ name: CSRF_COOKIE, value: csrf, url: page.url() }])
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.getByText('配置已安全保存')).toBeVisible()
  expect(saveCsrf).toBe(csrf)
})

test('settings save surfaces the csrf_failed envelope', async ({ page }) => {
  let saveCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/config', (route) => {
    if (route.request().method() === 'PUT') {
      saveCalls += 1
      return route.fulfill({
        status: 403,
        json: { error: { code: 'csrf_failed', message: 'CSRF 校验失败' } },
      })
    }
    return route.fulfill({ json: dashboardConfig })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: 'CSRF 校验失败' }).first()).toBeVisible()
  expect(saveCalls).toBe(1)
})

test('settings email test surfaces the enqueue_failed envelope', async ({ page }) => {
  let testCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/notifications/test/email', (route) => {
    testCalls += 1
    expect(route.request().method()).toBe('POST')
    return route.fulfill({
      status: 500,
      json: { error: { code: 'enqueue_failed', message: '任务提交失败' } },
    })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: '发送测试' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '任务提交失败' }).first()).toBeVisible()
  expect(testCalls).toBe(1)
})

test('settings telegram test surfaces the enqueue_failed envelope', async ({ page }) => {
  let testCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/notifications/test/telegram', (route) => {
    testCalls += 1
    expect(route.request().method()).toBe('POST')
    return route.fulfill({
      status: 500,
      json: { error: { code: 'enqueue_failed', message: '任务提交失败' } },
    })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: 'Telegram' }).click()
  await page.getByRole('button', { name: '发送测试' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '任务提交失败' }).first()).toBeVisible()
  expect(testCalls).toBe(1)
})

test('settings telegram socks5 proxy posts the live notify contract', async ({ page }) => {
  let savedTelegram: Record<string, unknown> | undefined
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/config', async (route) => {
    if (route.request().method() === 'PUT') {
      const payload = JSON.parse(route.request().postData() || '{}') as { notifications?: { telegram?: Record<string, unknown> } }
      expectKnownKeys(payload, CONFIG_OBJECT_KEYS)
      savedTelegram = payload.notifications?.telegram
      return route.fulfill({ json: { success: true } })
    }
    return route.fulfill({ json: dashboardConfig })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: 'Telegram' }).click()
  await page.getByText('启用 Telegram', { exact: true }).click()
  await page.getByLabel('Bot Token').fill('123:abc')
  await page.getByLabel('Chat ID').fill('-1001')
  await page.getByLabel('代理类型').click()
  await page.getByRole('option', { name: 'SOCKS5' }).click()
  await page.getByLabel('代理 IP').fill('127.0.0.1')
  await page.getByLabel('代理端口').fill('1080')
  await page.getByLabel('代理账号').fill('proxy-user')
  await page.getByLabel('代理密码').fill('proxy-pass')
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.getByText('配置已安全保存')).toBeVisible()
  expect(savedTelegram).toMatchObject({
    enabled: true,
    token: '123:abc',
    token_configured: false,
    chat_id: '-1001',
    proxy_type: 'socks5',
    proxy_url: '',
    proxy_ip: '127.0.0.1',
    proxy_port: '1080',
    proxy_user: 'proxy-user',
    proxy_pass: 'proxy-pass',
    proxy_password_configured: false,
  })
})

test('settings telegram custom proxy posts the live notify contract', async ({ page }) => {
  let savedTelegram: Record<string, unknown> | undefined
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/config', async (route) => {
    if (route.request().method() === 'PUT') {
      const payload = JSON.parse(route.request().postData() || '{}') as { notifications?: { telegram?: Record<string, unknown> } }
      expectKnownKeys(payload, CONFIG_OBJECT_KEYS)
      savedTelegram = payload.notifications?.telegram
      return route.fulfill({ json: { success: true } })
    }
    return route.fulfill({ json: dashboardConfig })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: 'Telegram' }).click()
  await page.getByText('启用 Telegram', { exact: true }).click()
  await page.getByLabel('Bot Token').fill('123:abc')
  await page.getByLabel('Chat ID').fill('-1001')
  await page.getByLabel('代理类型').click()
  await page.getByRole('option', { name: '自定义反代' }).click()
  await page.getByLabel('反代 URL').fill('https://telegram.example.invalid')
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.getByText('配置已安全保存')).toBeVisible()
  expect(savedTelegram).toMatchObject({
    enabled: true,
    token: '123:abc',
    token_configured: false,
    chat_id: '-1001',
    proxy_type: 'custom',
    proxy_url: 'https://telegram.example.invalid',
    proxy_ip: '',
    proxy_port: '',
    proxy_user: '',
    proxy_password_configured: false,
  })
})

test('settings bark webhook template requires a key', async ({ page }) => {
  let saveCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/config', (route) => {
    if (route.request().method() === 'PUT') {
      saveCalls += 1
      return route.fulfill({ json: { success: true } })
    }
    return route.fulfill({ json: dashboardConfig })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: 'Webhook' }).click()
  await page.locator('#webhook-template').click()
  await page.getByRole('option', { name: 'Bark' }).click()
  await page.getByRole('button', { name: '生成 Webhook' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '请填写 Key' }).first()).toBeVisible()
  await expect(page.getByRole('dialog', { name: 'Bark 模板配置' })).toBeVisible()
  expect(saveCalls).toBe(0)
})

test('settings email smtp posts the live notify contract', async ({ page }) => {
  let savedEmail: Record<string, unknown> | undefined
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/config', async (route) => {
    if (route.request().method() === 'PUT') {
      const payload = JSON.parse(route.request().postData() || '{}') as { notifications?: { email?: Record<string, unknown> } }
      expectKnownKeys(payload, CONFIG_OBJECT_KEYS)
      savedEmail = payload.notifications?.email
      return route.fulfill({ json: { success: true } })
    }
    return route.fulfill({ json: dashboardConfig })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByText('启用 Email', { exact: true }).click()
  await page.getByLabel('接收邮箱').fill('ops@example.invalid')
  await page.getByLabel('SMTP Host').fill('smtp.example.invalid')
  await page.getByLabel('端口').fill('587')
  await page.getByLabel('安全模式').click()
  await page.getByRole('option', { name: 'STARTTLS' }).click()
  await page.getByLabel('用户名').fill('ops')
  await page.getByLabel('密码', { exact: true }).fill('mail-pass')
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.getByText('配置已安全保存')).toBeVisible()
  expect(savedEmail).toMatchObject({
    enabled: true,
    to: 'ops@example.invalid',
    host: 'smtp.example.invalid',
    port: 587,
    username: 'ops',
    password: 'mail-pass',
    security: 'tls',
    password_configured: false,
  })
})

test('settings email test surfaces a failed notification job', async ({ page }) => {
  let testCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/notifications/test/email', (route) => {
    testCalls += 1
    expect(route.request().method()).toBe('POST')
    const job = jobFixture('notify-email-fail', 'queued')
    job.type = 'test_notification'
    return route.fulfill({ status: 202, json: job })
  })
  await page.route('**/api/v1/jobs/**', (route) => {
    const failed = jobFixture('notify-email-fail', 'failed')
    failed.type = 'test_notification'
    failed.error = 'SMTP host, port, username and recipient are required'
    return route.fulfill({ json: failed })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: '发送测试' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: 'SMTP host, port, username and recipient are required' }).first()).toBeVisible()
  expect(testCalls).toBe(1)
})

test('settings telegram test surfaces a failed notification job', async ({ page }) => {
  let testCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/notifications/test/telegram', (route) => {
    testCalls += 1
    expect(route.request().method()).toBe('POST')
    const job = jobFixture('notify-telegram-fail', 'queued')
    job.type = 'test_notification'
    return route.fulfill({ status: 202, json: job })
  })
  await page.route('**/api/v1/jobs/**', (route) => {
    const failed = jobFixture('notify-telegram-fail', 'failed')
    failed.type = 'test_notification'
    failed.error = 'telegram HTTP 401: unauthorized'
    return route.fulfill({ json: failed })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: 'Telegram' }).click()
  await page.getByRole('button', { name: '发送测试' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: 'telegram HTTP 401: unauthorized' }).first()).toBeVisible()
  expect(testCalls).toBe(1)
})

test('settings dingtalk webhook template requires a token', async ({ page }) => {
  let saveCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/config', (route) => {
    if (route.request().method() === 'PUT') {
      saveCalls += 1
      return route.fulfill({ json: { success: true } })
    }
    return route.fulfill({ json: dashboardConfig })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: 'Webhook' }).click()
  await page.locator('#webhook-template').click()
  await page.getByRole('option', { name: '钉钉群机器人' }).click()
  await page.getByRole('button', { name: '生成 Webhook' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '请填写机器人 Access Token' }).first()).toBeVisible()
  await expect(page.getByRole('dialog', { name: '钉钉群机器人 模板配置' })).toBeVisible()
  expect(saveCalls).toBe(0)
})

test('settings wecom webhook template requires a key', async ({ page }) => {
  let saveCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/config', (route) => {
    if (route.request().method() === 'PUT') {
      saveCalls += 1
      return route.fulfill({ json: { success: true } })
    }
    return route.fulfill({ json: dashboardConfig })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: 'Webhook' }).click()
  await page.locator('#webhook-template').click()
  await page.getByRole('option', { name: '微信群机器人' }).click()
  await page.getByRole('button', { name: '生成 Webhook' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '请填写 Key' }).first()).toBeVisible()
  await expect(page.getByRole('dialog', { name: '微信群机器人 模板配置' })).toBeVisible()
  expect(saveCalls).toBe(0)
})

test('settings wxpusher webhook template requires app token and uid', async ({ page }) => {
  let saveCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/config', (route) => {
    if (route.request().method() === 'PUT') {
      saveCalls += 1
      return route.fulfill({ json: { success: true } })
    }
    return route.fulfill({ json: dashboardConfig })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: 'Webhook' }).click()
  await page.locator('#webhook-template').click()
  await page.getByRole('option', { name: 'WxPusher' }).click()
  await page.getByRole('button', { name: '生成 Webhook' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '请填写 AppToken 和 UID' }).first()).toBeVisible()
  await expect(page.getByRole('dialog', { name: 'WxPusher 模板配置' })).toBeVisible()
  expect(saveCalls).toBe(0)
})

test('settings webhook form posts the live webhook contract', async ({ page }) => {
  let savedWebhook: Record<string, unknown> | undefined
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/config', async (route) => {
    if (route.request().method() === 'PUT') {
      const payload = JSON.parse(route.request().postData() || '{}') as { notifications?: { webhook?: Record<string, unknown> } }
      expectKnownKeys(payload, CONFIG_OBJECT_KEYS)
      savedWebhook = payload.notifications?.webhook
      return route.fulfill({ json: { success: true } })
    }
    return route.fulfill({ json: dashboardConfig })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: 'Webhook' }).click()
  await page.getByText('启用 Webhook', { exact: true }).click()
  await page.getByLabel('Webhook URL').fill('https://example.invalid/hook')
  await page.getByLabel('请求方式').click()
  await page.getByRole('option', { name: 'POST' }).click()
  await page.getByLabel('请求类型').click()
  await page.getByRole('option', { name: 'FORM' }).click()
  await page.getByLabel('自定义 Headers').fill('{"Authorization":"Bearer test"}')
  await page.getByLabel('Body 模板').fill('title=#TITLE#&message=#MSG#')
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.getByText('配置已安全保存')).toBeVisible()
  expect(savedWebhook).toMatchObject({
    enabled: true,
    url: 'https://example.invalid/hook',
    method: 'POST',
    request_type: 'FORM',
    headers: '{"Authorization":"Bearer test"}',
    body: 'title=#TITLE#&message=#MSG#',
    secret_configured: false,
  })
})

test('settings email smtp none posts the live notify contract', async ({ page }) => {
  let savedEmail: Record<string, unknown> | undefined
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/config', async (route) => {
    if (route.request().method() === 'PUT') {
      const payload = JSON.parse(route.request().postData() || '{}') as { notifications?: { email?: Record<string, unknown> } }
      expectKnownKeys(payload, CONFIG_OBJECT_KEYS)
      savedEmail = payload.notifications?.email
      return route.fulfill({ json: { success: true } })
    }
    return route.fulfill({ json: dashboardConfig })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByText('启用 Email', { exact: true }).click()
  await page.getByLabel('接收邮箱').fill('ops@example.invalid')
  await page.getByLabel('SMTP Host').fill('smtp.example.invalid')
  await page.getByLabel('端口').fill('25')
  await page.getByLabel('安全模式').click()
  await page.getByRole('option', { name: '无' }).click()
  await page.getByLabel('用户名').fill('ops')
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.getByText('配置已安全保存')).toBeVisible()
  expect(savedEmail).toMatchObject({
    enabled: true,
    to: 'ops@example.invalid',
    host: 'smtp.example.invalid',
    port: 25,
    username: 'ops',
    security: 'none',
    password_configured: false,
  })
})

test('about update check surfaces the live check_error contract', async ({ page }) => {
  let checkCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/system/info**', (route) => {
    const check = new URL(route.request().url()).searchParams.get('check') === '1'
    if (check) checkCalls += 1
    return route.fulfill({ json: {
      version: 'v2.0.1',
      commit: 'abc1234',
      built_at: 'github-run-12345',
      repository: 'https://github.com/wang4386/CDT-Monitor',
      release_url: 'https://github.com/wang4386/CDT-Monitor/releases',
      ...(check ? { check_error: '暂时无法检查 GitHub Release' } : {}),
    } })
  })
  await page.route('https://api.github.com/repos/wang4386/CDT-Monitor/releases/latest', (route) => route.fulfill({
    status: 403,
    headers: { 'access-control-allow-origin': '*' },
    json: { message: 'API rate limit exceeded' },
  }))

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '关于' }).click()
  await page.getByRole('button', { name: '检查更新' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '暂时无法检查 GitHub Release' }).first()).toBeVisible()
  expect(checkCalls).toBe(1)
})

test('history chart daily range renders empty sampling state from the history contract', async ({ page }) => {
  const hourStart = Math.floor(Date.now() / 3_600_000) * 3_600_000
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/accounts/1/history', (route) => route.fulfill({ json: {
    hourly: [{ at: new Date(hourStart).toISOString(), traffic: 1.25 }],
    daily: [],
  } }))

  await page.goto('/')
  await page.getByRole('button', { name: '查看历史流量' }).click()
  await expect(page.locator('.chart-area .recharts-wrapper')).toBeVisible()
  await page.getByRole('button', { name: '30 天' }).click()
  await expect(page.getByText('等待采样数据')).toBeVisible()
  await expect(page.locator('.chart-area .recharts-wrapper')).toHaveCount(0)
})

test('settings save posts notify_only threshold action', async ({ page }) => {
  let saveCalls = 0
  let thresholdAction = ''
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/config', async (route) => {
    if (route.request().method() === 'PUT') {
      saveCalls += 1
      const body = JSON.parse(route.request().postData() || '{}') as Record<string, unknown>
      expectKnownKeys(body, CONFIG_OBJECT_KEYS)
      thresholdAction = String(body.threshold_action || '')
      return route.fulfill({ json: { success: true } })
    }
    return route.fulfill({ json: dashboardConfig })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '仅通知' }).click()
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.getByText('配置已安全保存')).toBeVisible()
  expect(saveCalls).toBe(1)
  expect(thresholdAction).toBe('notify_only')
})

test('settings save posts StopCharging shutdown mode', async ({ page }) => {
  let saveCalls = 0
  let shutdownMode = ''
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/config', async (route) => {
    if (route.request().method() === 'PUT') {
      saveCalls += 1
      const body = JSON.parse(route.request().postData() || '{}') as Record<string, unknown>
      expectKnownKeys(body, CONFIG_OBJECT_KEYS)
      shutdownMode = String(body.shutdown_mode || '')
      return route.fulfill({ json: { success: true } })
    }
    return route.fulfill({ json: dashboardConfig })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '节省停机' }).click()
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.getByText('配置已安全保存')).toBeVisible()
  expect(saveCalls).toBe(1)
  expect(shutdownMode).toBe('StopCharging')
})

test('settings save posts custom api_interval', async ({ page }) => {
  let saveCalls = 0
  let interval: number | undefined
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/config', async (route) => {
    if (route.request().method() === 'PUT') {
      saveCalls += 1
      const body = JSON.parse(route.request().postData() || '{}') as Record<string, unknown>
      expectKnownKeys(body, CONFIG_OBJECT_KEYS)
      interval = Number(body.api_interval)
      return route.fulfill({ json: { success: true } })
    }
    return route.fulfill({ json: dashboardConfig })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('combobox', { name: 'API 刷新间隔' }).click()
  await page.getByRole('option', { name: '自定义' }).click()
  await page.getByLabel('自定义间隔').fill('45')
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.getByText('配置已安全保存')).toBeVisible()
  expect(saveCalls).toBe(1)
  expect(interval).toBe(45)
})

test('settings save posts keep_alive enabled', async ({ page }) => {
  let saveCalls = 0
  let keepAlive: boolean | undefined
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/config', async (route) => {
    if (route.request().method() === 'PUT') {
      saveCalls += 1
      const body = JSON.parse(route.request().postData() || '{}') as Record<string, unknown>
      expectKnownKeys(body, CONFIG_OBJECT_KEYS)
      keepAlive = Boolean(body.keep_alive)
      return route.fulfill({ json: { success: true } })
    }
    return route.fulfill({ json: dashboardConfig })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByText('抢占式实例保活', { exact: true }).click()
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.getByText('配置已安全保存')).toBeVisible()
  expect(saveCalls).toBe(1)
  expect(keepAlive).toBe(true)
})

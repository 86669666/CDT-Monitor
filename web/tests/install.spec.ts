import { expect, test } from '@playwright/test'
import { CSRF_COOKIE, CSRF_HEADER, JOB_FAILED_USER_MESSAGE } from '../src/api'
import { MAX_ACCOUNTS, MAX_ACCOUNT_REMARK_RUNES, MAX_ACCOUNT_TRAFFIC_GB, MAX_ACCESS_KEY_ID_CHARS, MAX_INSTANCE_ID_CHARS, MAX_TELEGRAM_CHAT_RUNES, MAX_NOTIFY_EMAIL_RUNES, MAX_NOTIFY_TCP_PORT, MAX_WEBHOOK_HEADERS_RUNES, MAX_WEBHOOK_BODY_RUNES, MAX_NOTIFY_URL_RUNES, MAX_NOTIFY_SECRET_RUNES, MAX_NOTIFY_DIAL_HOST_RUNES, MAX_TIMEZONE_RUNES, MAX_PASSWORD_RUNES, MAX_ACCESS_KEY_SECRET_RUNES, MAX_API_KEYS, MAX_PASSKEYS, MAX_PASSKEY_NAME_RUNES, MAX_API_KEY_NAME_RUNES, liveScheduleClock, liveNotifyHeaderText } from '../src/types'
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
  liveGetEmail,
  liveGetTelegram,
  liveGetWebhook,
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
  expect(notifications.email).not.toHaveProperty('password')
  expect(notifications.telegram).toMatchObject({ enabled: false, token_configured: false, proxy_type: 'none', proxy_password_configured: false })
  expect(notifications.telegram).not.toHaveProperty('token')
  expect(notifications.telegram).not.toHaveProperty('proxy_url')
  expect(notifications.telegram).not.toHaveProperty('proxy_pass')
  expect(notifications.webhook).toMatchObject({ enabled: false, method: 'GET', request_type: 'JSON', provider: 'generic', secret_configured: false, headers_configured: false, url_configured: false, body_configured: false })
  expect(notifications.webhook).not.toHaveProperty('url')
  expect(notifications.webhook).not.toHaveProperty('headers')
  expect(notifications.webhook).not.toHaveProperty('body')
  expect(notifications.webhook).not.toHaveProperty('secret')
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

test('wizard surfaces the live setup_failed fallback envelope', async ({ page }) => {
  await mockInitStatus(page, false)
  await page.route('**/api/v1/setup', (route) => route.fulfill({
    status: 400,
    json: { error: { code: 'setup_failed', message: '系统初始化失败' } },
  }))

  await page.goto('/')
  const passwords = page.locator('input[type="password"]')
  await passwords.nth(0).fill(TEST_PASSWORD)
  await passwords.nth(1).fill(TEST_PASSWORD)
  await page.getByRole('button', { name: '继续' }).click()
  await page.getByRole('button', { name: '继续' }).click()
  await page.getByRole('button', { name: '完成安装' }).click()
  await expect(page.getByText('系统初始化失败')).toBeVisible()
  await expect(page.getByRole('heading', { name: '连接云端实例' })).toBeVisible()
})

test('wizard surfaces the live invalid timezone setup_failed envelope', async ({ page }) => {
  await mockInitStatus(page, false)
  let setupCalls = 0
  await page.route('**/api/v1/setup', (route) => {
    setupCalls += 1
    const body = JSON.parse(route.request().postData() || '{}') as { timezone?: string }
    expect(body.timezone).toBe('Not/AZone')
    return route.fulfill({
      status: 400,
      json: { error: { code: 'setup_failed', message: 'invalid timezone' } },
    })
  })

  await page.goto('/')
  const passwords = page.locator('input[type="password"]')
  await passwords.nth(0).fill(TEST_PASSWORD)
  await passwords.nth(1).fill(TEST_PASSWORD)
  await page.getByRole('button', { name: '继续' }).click()
  await page.getByLabel('系统时区').fill('Not/AZone')
  await page.getByRole('button', { name: '继续' }).click()
  await page.getByRole('button', { name: '完成安装' }).click()
  await expect(page.getByText('invalid timezone')).toBeVisible()
  await expect(page.getByRole('heading', { name: '连接云端实例' })).toBeVisible()
  expect(setupCalls).toBe(1)
})

test('wizard surfaces the live traffic threshold setup_failed envelope', async ({ page }) => {
  await mockInitStatus(page, false)
  let setupCalls = 0
  await page.route('**/api/v1/setup', (route) => {
    setupCalls += 1
    const body = JSON.parse(route.request().postData() || '{}') as { traffic_threshold?: number }
    expect(body.traffic_threshold).toBe(0)
    return route.fulfill({
      status: 400,
      json: { error: { code: 'setup_failed', message: 'traffic threshold must be between 1 and 100' } },
    })
  })

  await page.goto('/')
  const passwords = page.locator('input[type="password"]')
  await passwords.nth(0).fill(TEST_PASSWORD)
  await passwords.nth(1).fill(TEST_PASSWORD)
  await page.getByRole('button', { name: '继续' }).click()
  await page.getByLabel('流量告警阈值').fill('')
  await page.getByRole('button', { name: '继续' }).click()
  await page.getByRole('button', { name: '完成安装' }).click()
  await expect(page.getByText('traffic threshold must be between 1 and 100')).toBeVisible()
  await expect(page.getByRole('heading', { name: '连接云端实例' })).toBeVisible()
  expect(setupCalls).toBe(1)
})

test('wizard surfaces the live over-max traffic threshold setup_failed envelope', async ({ page }) => {
  await mockInitStatus(page, false)
  let setupCalls = 0
  await page.route('**/api/v1/setup', (route) => {
    setupCalls += 1
    const body = JSON.parse(route.request().postData() || '{}') as { traffic_threshold?: number }
    expect(body.traffic_threshold).toBe(101)
    return route.fulfill({
      status: 400,
      json: { error: { code: 'setup_failed', message: 'traffic threshold must be between 1 and 100' } },
    })
  })

  await page.goto('/')
  const passwords = page.locator('input[type="password"]')
  await passwords.nth(0).fill(TEST_PASSWORD)
  await passwords.nth(1).fill(TEST_PASSWORD)
  await page.getByRole('button', { name: '继续' }).click()
  await page.getByLabel('流量告警阈值').fill('101')
  await page.getByRole('button', { name: '继续' }).click()
  await page.getByRole('button', { name: '完成安装' }).click()
  await expect(page.getByText('traffic threshold must be between 1 and 100')).toBeVisible()
  await expect(page.getByRole('heading', { name: '连接云端实例' })).toBeVisible()
  expect(setupCalls).toBe(1)
})

test('wizard surfaces the live missing account secret setup_failed envelope', async ({ page }) => {
  await mockInitStatus(page, false)
  let setupCalls = 0
  await page.route('**/api/v1/setup', (route) => {
    setupCalls += 1
    const body = JSON.parse(route.request().postData() || '{}') as { accounts?: Record<string, unknown>[] }
    expect(body.accounts).toHaveLength(1)
    expect(body.accounts?.[0]).toMatchObject({ access_key_id: 'LTAI5added', secret_configured: false })
    expect(body.accounts?.[0]).not.toHaveProperty('access_key_secret')
    return route.fulfill({
      status: 400,
      json: { error: { code: 'setup_failed', message: 'account LTAI5added is missing access key secret' } },
    })
  })

  await page.goto('/')
  const passwords = page.locator('input[type="password"]')
  await passwords.nth(0).fill(TEST_PASSWORD)
  await passwords.nth(1).fill(TEST_PASSWORD)
  await page.getByRole('button', { name: '继续' }).click()
  await page.getByRole('button', { name: '继续' }).click()
  await page.getByLabel('AccessKey ID').fill('LTAI5added')
  await page.getByLabel('实例 ID').fill('i-added')
  await page.getByRole('button', { name: '完成安装' }).click()
  await expect(page.getByText('account LTAI5added is missing access key secret')).toBeVisible()
  await expect(page.getByRole('heading', { name: '连接云端实例' })).toBeVisible()
  expect(setupCalls).toBe(1)
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

test('setup clamps custom api_interval to the live minimum', async ({ page }) => {
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
  await page.getByRole('combobox', { name: '状态刷新频率' }).click()
  await page.getByRole('option', { name: '自定义' }).click()
  await page.getByLabel('自定义间隔').fill('1')
  await page.getByRole('button', { name: '继续' }).click()
  await page.getByRole('button', { name: '完成安装' }).click()
  await expect(page.getByRole('heading', { name: '资源控制台' })).toBeVisible({ timeout: 30_000 })
  expect(interval).toBe(30)
})

test('setup clamps custom api_interval to the live maximum', async ({ page }) => {
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
  await page.getByRole('combobox', { name: '状态刷新频率' }).click()
  await page.getByRole('option', { name: '自定义' }).click()
  await page.getByLabel('自定义间隔').fill('99999')
  await page.getByRole('button', { name: '继续' }).click()
  await page.getByRole('button', { name: '完成安装' }).click()
  await expect(page.getByRole('heading', { name: '资源控制台' })).toBeVisible({ timeout: 30_000 })
  expect(interval).toBe(86400)
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

test('init-status failure surfaces the live database_not_ready envelope', async ({ page }) => {
  await page.route('**/api/v1/system/init-status', (route) => route.fulfill({
    status: 503,
    json: { error: { code: 'database_not_ready', message: '数据库暂时不可用' } },
  }))

  await page.goto('/')
  await expect(page.getByRole('heading', { name: '控制台暂时不可用' })).toBeVisible()
  await expect(page.getByText('数据库暂时不可用')).toBeVisible()
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

test('login surfaces the live internal_error envelope', async ({ page }) => {
  await mockInitStatus(page, true)
  await mockUnauthorizedSession(page)
  await page.route('**/api/v1/auth/login', (route) => route.fulfill({
    status: 500,
    json: { error: { code: 'internal_error', message: '服务暂时不可用' } },
  }))

  await page.goto('/')
  await page.getByLabel('管理员密码').fill(TEST_PASSWORD)
  await page.getByRole('button', { name: '安全登录' }).click()
  await expect(page.getByText('服务暂时不可用')).toBeVisible()
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


test('failed start job surfaces a generic failure toast', async ({ page }) => {
  const leaked = 'FIXTURE-SECRET-TOKEN'
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
    failed.error = `aliyun HTTP 403: AccessKeyId=${leaked}`
    return route.fulfill({ json: failed })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '开机' }).click()
  await expect(page.getByText(JOB_FAILED_USER_MESSAGE)).toBeVisible()
  await expect(page.locator('.toast-stack')).not.toContainText(leaked)
})

test('instance start timeout surfaces the in-progress job message', async ({ page }) => {
  await page.clock.install()
  await mockInitStatus(page, true)
  await mockDashboardReads(page, {
    ...dashboardStatus,
    accounts: [{ ...dashboardAccount, instance_status: 'Stopped' }],
  })
  await page.route('**/api/v1/accounts/1/actions/start', (route) => {
    expect(route.request().method()).toBe('POST')
    return route.fulfill({ status: 202, json: jobFixture('start-timeout', 'queued', 1) })
  })
  await page.route('**/api/v1/jobs/**', (route) => {
    const queued = jobFixture('start-timeout', 'queued', 1)
    queued.error = 'FIXTURE-SECRET-TOKEN'
    return route.fulfill({ json: queued })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '开机' }).click()
  await page.clock.fastForward(71_000)
  await expect(page.locator('.toast--error').filter({ hasText: '任务仍在后台执行，请稍后刷新' }).first()).toBeVisible()
  await expect(page.locator('.toast-stack')).not.toContainText('FIXTURE-SECRET-TOKEN')
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
    json: { error: { code: 'invalid_request', message: '请求体无效' } },
  }))

  await page.goto('/')
  await page.getByLabel('管理员密码').fill(TEST_PASSWORD)
  await page.getByRole('button', { name: '安全登录' }).click()
  await expect(page.getByText('请求体无效')).toBeVisible()
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
  await expect(page.locator('.toast--error').filter({ hasText: JOB_FAILED_USER_MESSAGE }).first()).toBeVisible()
  expect(testCalls).toBe(1)
})

test('failed webhook notify job toast omits transport secrets', async ({ page }) => {
  const leaked = 'FIXTURE-SECRET-TOKEN'
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/notifications/test/webhook', (route) => {
    expect(route.request().method()).toBe('POST')
    const job = jobFixture('notify-webhook-secret', 'queued')
    job.type = 'test_notification'
    return route.fulfill({ status: 202, json: job })
  })
  await page.route('**/api/v1/jobs/**', (route) => {
    const failed = jobFixture('notify-webhook-secret', 'failed')
    failed.type = 'test_notification'
    failed.error = `webhook HTTP 401: Authorization Bearer ${leaked}`
    return route.fulfill({ json: failed })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: 'Webhook' }).click()
  await page.getByRole('button', { name: '发送测试' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: JOB_FAILED_USER_MESSAGE }).first()).toBeVisible()
  await expect(page.locator('.toast-stack')).not.toContainText(leaked)
})

test('webhook notify timeout surfaces the in-progress job message', async ({ page }) => {
  await page.clock.install()
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/notifications/test/webhook', (route) => {
    expect(route.request().method()).toBe('POST')
    const job = jobFixture('notify-webhook-timeout', 'queued')
    job.type = 'test_notification'
    return route.fulfill({ status: 202, json: job })
  })
  await page.route('**/api/v1/jobs/**', (route) => {
    const queued = jobFixture('notify-webhook-timeout', 'queued')
    queued.type = 'test_notification'
    queued.error = 'FIXTURE-SECRET-TOKEN'
    return route.fulfill({ json: queued })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: 'Webhook' }).click()
  const jobPolled = page.waitForRequest('**/api/v1/jobs/**')
  await page.getByRole('button', { name: '发送测试' }).click()
  await jobPolled
  await page.clock.fastForward(71_000)
  await expect(page.locator('.toast--error').filter({ hasText: '任务仍在后台执行，请稍后刷新' }).first()).toBeVisible()
  await expect(page.locator('.toast-stack')).not.toContainText('FIXTURE-SECRET-TOKEN')
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
    json: { error: { code: 'api_keys_failed', message: 'API Key 加载失败' } },
  }))

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: 'API Key' }).click()
  await expect(page.locator('.inline-error')).toContainText('API Key 加载失败')
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
        json: { error: { code: 'api_key_failed', message: 'API Key 创建失败' } },
      })
    }
    return route.fulfill({ json: { keys: [] } })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: 'API Key' }).click()
  await page.getByRole('button', { name: '创建 Key' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: 'API Key 创建失败' }).first()).toBeVisible()
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

test('settings save surfaces the live invalid timezone envelope', async ({ page }) => {
  let saveCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/config', (route) => {
    if (route.request().method() === 'PUT') {
      saveCalls += 1
      const body = JSON.parse(route.request().postData() || '{}') as { timezone?: string }
      expect(body.timezone).toBe('Not/AZone')
      return route.fulfill({
        status: 400,
        json: { error: { code: 'config_failed', message: 'invalid timezone' } },
      })
    }
    return route.fulfill({ json: dashboardConfig })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByLabel('系统时区').fill('Not/AZone')
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: 'invalid timezone' }).first()).toBeVisible()
  expect(saveCalls).toBe(1)
})

test('settings save surfaces the live traffic threshold envelope', async ({ page }) => {
  let saveCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/config', (route) => {
    if (route.request().method() === 'PUT') {
      saveCalls += 1
      const body = JSON.parse(route.request().postData() || '{}') as { traffic_threshold?: number }
      expect(body.traffic_threshold).toBe(0)
      return route.fulfill({
        status: 400,
        json: { error: { code: 'config_failed', message: 'traffic threshold must be between 1 and 100' } },
      })
    }
    return route.fulfill({ json: dashboardConfig })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByLabel('告警阈值').fill('')
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: 'traffic threshold must be between 1 and 100' }).first()).toBeVisible()
  expect(saveCalls).toBe(1)
})

test('settings save surfaces the live over-max traffic threshold envelope', async ({ page }) => {
  let saveCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/config', (route) => {
    if (route.request().method() === 'PUT') {
      saveCalls += 1
      const body = JSON.parse(route.request().postData() || '{}') as { traffic_threshold?: number }
      expect(body.traffic_threshold).toBe(101)
      return route.fulfill({
        status: 400,
        json: { error: { code: 'config_failed', message: 'traffic threshold must be between 1 and 100' } },
      })
    }
    return route.fulfill({ json: dashboardConfig })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByLabel('告警阈值').fill('101')
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: 'traffic threshold must be between 1 and 100' }).first()).toBeVisible()
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
    headers: '__clear__',
    url: 'https://api.day.app/test-key/#TITLE#/#MSG#',
    body: '__clear__',
    secret: '',
    secret_configured: false,
  })
})

test('settings bark webhook template clears configured headers with the live sentinel', async ({ page }) => {
  const configured = {
    ...dashboardConfig,
    notifications: {
      ...dashboardConfig.notifications,
      webhook: liveGetWebhook({
        enabled: true,
        method: 'POST',
        request_type: 'JSON',
        headers_configured: true,
        url_configured: true,
        body_configured: true,
      }),
    },
  }
  let savedWebhook: Record<string, unknown> | undefined
  await mockInitStatus(page, true)
  await mockDashboardReads(page, dashboardStatus, configured)
  await page.route('**/api/v1/config', async (route) => {
    if (route.request().method() === 'PUT') {
      const body = JSON.parse(route.request().postData() || '{}') as { notifications?: { webhook?: Record<string, unknown> } }
      expectKnownKeys(body, CONFIG_OBJECT_KEYS)
      savedWebhook = body.notifications?.webhook
      return route.fulfill({ json: { success: true } })
    }
    return route.fulfill({ json: configured })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: 'Webhook' }).click()
  await expect(page.getByLabel('自定义 Headers · 已配置')).toHaveValue('')
  await expect(page.getByLabel('Webhook URL · 已配置')).toHaveValue('')
  await expect(page.getByLabel('Body 模板 · 已配置')).toHaveValue('')
  await page.locator('#webhook-template').click()
  await page.getByRole('option', { name: 'Bark' }).click()
  await page.getByLabel('Bark Key').fill('test-key')
  await page.getByRole('button', { name: '生成 Webhook' }).click()
  await expect(page.getByText('Bark 模板已生成，请检查后保存')).toBeVisible()
  await expect(page.getByText('__clear__')).toHaveCount(0)
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.getByText('配置已安全保存')).toBeVisible()
  expect(savedWebhook).toMatchObject({
    enabled: true,
    provider: 'bark',
    method: 'GET',
    headers: '__clear__',
    body: '__clear__',
    url: 'https://api.day.app/test-key/#TITLE#/#MSG#',
  })
  expect(savedWebhook?.headers).not.toBe('')
  expect(savedWebhook?.body).not.toBe('')
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

test('failed refresh job surfaces a generic failure toast', async ({ page }) => {
  const leaked = 'FIXTURE-SECRET-TOKEN'
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/accounts/1/refresh', (route) => {
    expect(route.request().method()).toBe('POST')
    return route.fulfill({ status: 202, json: jobFixture('refresh-secret-fail', 'queued', 1) })
  })
  await page.route('**/api/v1/jobs/**', (route) => {
    const failed = jobFixture('refresh-secret-fail', 'failed', 1)
    failed.error = `aliyun HTTP 403: AccessKeyId=${leaked}`
    return route.fulfill({ json: failed })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '刷新实例' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: JOB_FAILED_USER_MESSAGE }).first()).toBeVisible()
  await expect(page.locator('.toast-stack')).not.toContainText(leaked)
})

test('instance refresh timeout surfaces the in-progress job message', async ({ page }) => {
  await page.clock.install()
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/accounts/1/refresh', (route) => {
    expect(route.request().method()).toBe('POST')
    return route.fulfill({ status: 202, json: jobFixture('refresh-timeout', 'queued', 1) })
  })
  await page.route('**/api/v1/jobs/**', (route) => {
    const queued = jobFixture('refresh-timeout', 'queued', 1)
    queued.error = 'FIXTURE-SECRET-TOKEN'
    return route.fulfill({ json: queued })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '刷新实例' }).click()
  await page.clock.fastForward(71_000)
  await expect(page.locator('.toast--error').filter({ hasText: '任务仍在后台执行，请稍后刷新' }).first()).toBeVisible()
  await expect(page.locator('.toast-stack')).not.toContainText('FIXTURE-SECRET-TOKEN')
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
  await expect(page.getByText('尚未创建管理员 Passkey')).toBeVisible()
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
  await expect(page.getByText('尚未创建管理员 Passkey')).toBeVisible()
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
        json: { error: { code: 'invalid_request', message: '请求体无效' } },
      })
    }
    return route.fulfill({ json: dashboardConfig })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '请求体无效' }).first()).toBeVisible()
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
    headers: '__clear__',
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
    headers: '__clear__',
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
    headers: '__clear__',
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
      json: { error: { code: 'api_key_failed', message: 'API Key 操作失败' } },
    })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: 'API Key' }).click()
  await page.getByRole('button', { name: '撤销' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: 'API Key 操作失败' }).first()).toBeVisible()
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
    proxy_ip: '127.0.0.1',
    proxy_port: '1080',
    proxy_user: 'proxy-user',
    proxy_pass: 'proxy-pass',
    proxy_password_configured: false,
  })
  expect(savedTelegram).not.toHaveProperty('proxy_url')
})

test('settings telegram keeps configured proxy password when left empty', async ({ page }) => {
  const configured = {
    ...dashboardConfig,
    notifications: {
      ...dashboardConfig.notifications,
      telegram: liveGetTelegram({
        enabled: true,
        token_configured: true,
        chat_id: '-1001',
        proxy_type: 'socks5',
        proxy_ip: '127.0.0.1',
        proxy_port: '1080',
        proxy_user: 'proxy-user',
        proxy_password_configured: true,
      }),
    },
  }
  let savedTelegram: Record<string, unknown> | undefined
  await mockInitStatus(page, true)
  await mockDashboardReads(page, dashboardStatus, configured)
  await page.route('**/api/v1/config', async (route) => {
    if (route.request().method() === 'PUT') {
      const payload = JSON.parse(route.request().postData() || '{}') as { notifications?: { telegram?: Record<string, unknown> } }
      expectKnownKeys(payload, CONFIG_OBJECT_KEYS)
      savedTelegram = payload.notifications?.telegram
      return route.fulfill({ json: { success: true } })
    }
    return route.fulfill({ json: configured })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: 'Telegram' }).click()
  const passwordField = page.getByLabel('代理密码 · 已配置')
  await expect(passwordField).toBeVisible()
  await expect(passwordField).toHaveAttribute('placeholder', '留空保持不变')
  await expect(passwordField).toHaveValue('')
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.getByText('配置已安全保存')).toBeVisible()
  expect(savedTelegram).toMatchObject({
    enabled: true,
    proxy_type: 'socks5',
    proxy_password_configured: true,
  })
  expect(savedTelegram).not.toHaveProperty('proxy_pass')
  expect(JSON.stringify(savedTelegram)).not.toContain('__clear__')
})

test('settings telegram clears configured proxy password with the live sentinel', async ({ page }) => {
  const configured = {
    ...dashboardConfig,
    notifications: {
      ...dashboardConfig.notifications,
      telegram: liveGetTelegram({
        enabled: true,
        token_configured: true,
        chat_id: '-1001',
        proxy_type: 'socks5',
        proxy_ip: '127.0.0.1',
        proxy_port: '1080',
        proxy_user: 'proxy-user',
        proxy_password_configured: true,
      }),
    },
  }
  let savedTelegram: Record<string, unknown> | undefined
  await mockInitStatus(page, true)
  await mockDashboardReads(page, dashboardStatus, configured)
  await page.route('**/api/v1/config', async (route) => {
    if (route.request().method() === 'PUT') {
      const payload = JSON.parse(route.request().postData() || '{}') as { notifications?: { telegram?: Record<string, unknown> } }
      expectKnownKeys(payload, CONFIG_OBJECT_KEYS)
      savedTelegram = payload.notifications?.telegram
      return route.fulfill({ json: { success: true } })
    }
    return route.fulfill({ json: configured })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: 'Telegram' }).click()
  const passwordField = page.getByLabel('代理密码 · 已配置')
  await expect(passwordField).toHaveValue('')
  await expect(page.getByText('__clear__')).toHaveCount(0)
  await page.getByText('清除已配置的代理密码', { exact: true }).click()
  await expect(passwordField).toHaveAttribute('placeholder', '保存后清除')
  await expect(passwordField).toHaveValue('')
  await expect(page.getByText('__clear__')).toHaveCount(0)
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.getByText('配置已安全保存')).toBeVisible()
  expect(savedTelegram).toMatchObject({
    enabled: true,
    proxy_type: 'socks5',
    proxy_pass: '__clear__',
    proxy_password_configured: true,
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

test('settings telegram keeps configured proxy url when left empty', async ({ page }) => {
  const configured = {
    ...dashboardConfig,
    notifications: {
      ...dashboardConfig.notifications,
      telegram: liveGetTelegram({
        enabled: true,
        token_configured: true,
        chat_id: '-1001',
        proxy_type: 'custom',
        proxy_url_configured: true,
      }),
    },
  }
  let savedTelegram: Record<string, unknown> | undefined
  await mockInitStatus(page, true)
  await mockDashboardReads(page, dashboardStatus, configured)
  await page.route('**/api/v1/config', async (route) => {
    if (route.request().method() === 'PUT') {
      const payload = JSON.parse(route.request().postData() || '{}') as { notifications?: { telegram?: Record<string, unknown> } }
      expectKnownKeys(payload, CONFIG_OBJECT_KEYS)
      savedTelegram = payload.notifications?.telegram
      return route.fulfill({ json: { success: true } })
    }
    return route.fulfill({ json: configured })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: 'Telegram' }).click()
  const urlField = page.getByLabel('反代 URL · 已配置')
  await expect(urlField).toBeVisible()
  await expect(urlField).toHaveAttribute('placeholder', '留空保持不变')
  await expect(urlField).toHaveValue('')
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.getByText('配置已安全保存')).toBeVisible()
  expect(savedTelegram).toMatchObject({
    enabled: true,
    proxy_type: 'custom',
    proxy_url_configured: true,
  })
  expect(savedTelegram).not.toHaveProperty('proxy_url')
  expect(JSON.stringify(savedTelegram)).not.toContain('__clear__')
})

test('settings telegram clears configured proxy url with the live sentinel', async ({ page }) => {
  const configured = {
    ...dashboardConfig,
    notifications: {
      ...dashboardConfig.notifications,
      telegram: liveGetTelegram({
        enabled: true,
        token_configured: true,
        chat_id: '-1001',
        proxy_type: 'custom',
        proxy_url_configured: true,
      }),
    },
  }
  let savedTelegram: Record<string, unknown> | undefined
  await mockInitStatus(page, true)
  await mockDashboardReads(page, dashboardStatus, configured)
  await page.route('**/api/v1/config', async (route) => {
    if (route.request().method() === 'PUT') {
      const payload = JSON.parse(route.request().postData() || '{}') as { notifications?: { telegram?: Record<string, unknown> } }
      expectKnownKeys(payload, CONFIG_OBJECT_KEYS)
      savedTelegram = payload.notifications?.telegram
      return route.fulfill({ json: { success: true } })
    }
    return route.fulfill({ json: configured })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: 'Telegram' }).click()
  const urlField = page.getByLabel('反代 URL · 已配置')
  await expect(urlField).toHaveValue('')
  await expect(page.getByText('__clear__')).toHaveCount(0)
  await page.getByText('清除已配置的反代 URL', { exact: true }).click()
  await expect(urlField).toHaveAttribute('placeholder', '保存后清除')
  await expect(urlField).toHaveValue('')
  await expect(page.getByText('__clear__')).toHaveCount(0)
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.getByText('配置已安全保存')).toBeVisible()
  expect(savedTelegram).toMatchObject({
    enabled: true,
    proxy_type: 'custom',
    proxy_url: '__clear__',
    proxy_url_configured: true,
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
  await expect(page.locator('.toast--error').filter({ hasText: JOB_FAILED_USER_MESSAGE }).first()).toBeVisible()
  expect(testCalls).toBe(1)
})

test('failed email notify job toast omits transport secrets', async ({ page }) => {
  const leaked = 'FIXTURE-SECRET-TOKEN'
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/notifications/test/email', (route) => {
    expect(route.request().method()).toBe('POST')
    const job = jobFixture('notify-email-secret', 'queued')
    job.type = 'test_notification'
    return route.fulfill({ status: 202, json: job })
  })
  await page.route('**/api/v1/jobs/**', (route) => {
    const failed = jobFixture('notify-email-secret', 'failed')
    failed.type = 'test_notification'
    failed.error = `smtp auth failed: password=${leaked}`
    return route.fulfill({ json: failed })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: '发送测试' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: JOB_FAILED_USER_MESSAGE }).first()).toBeVisible()
  await expect(page.locator('.toast-stack')).not.toContainText(leaked)
})

test('email notify timeout surfaces the in-progress job message', async ({ page }) => {
  await page.clock.install()
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/notifications/test/email', (route) => {
    expect(route.request().method()).toBe('POST')
    const job = jobFixture('notify-email-timeout', 'queued')
    job.type = 'test_notification'
    return route.fulfill({ status: 202, json: job })
  })
  await page.route('**/api/v1/jobs/**', (route) => {
    const queued = jobFixture('notify-email-timeout', 'queued')
    queued.type = 'test_notification'
    queued.error = 'FIXTURE-SECRET-TOKEN'
    return route.fulfill({ json: queued })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  const jobPolled = page.waitForRequest('**/api/v1/jobs/**')
  await page.getByRole('button', { name: '发送测试' }).click()
  await jobPolled
  await page.clock.fastForward(71_000)
  await expect(page.locator('.toast--error').filter({ hasText: '任务仍在后台执行，请稍后刷新' }).first()).toBeVisible()
  await expect(page.locator('.toast-stack')).not.toContainText('FIXTURE-SECRET-TOKEN')
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
  await expect(page.locator('.toast--error').filter({ hasText: JOB_FAILED_USER_MESSAGE }).first()).toBeVisible()
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

test('settings save clamps custom api_interval to the live minimum', async ({ page }) => {
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
  await page.getByLabel('自定义间隔').fill('1')
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.getByText('配置已安全保存')).toBeVisible()
  expect(saveCalls).toBe(1)
  expect(interval).toBe(30)
})

test('settings save clamps custom api_interval to the live maximum', async ({ page }) => {
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
  await page.getByLabel('自定义间隔').fill('99999')
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.getByText('配置已安全保存')).toBeVisible()
  expect(saveCalls).toBe(1)
  expect(interval).toBe(86400)
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

test('about update check posts the live latest_version contract', async ({ page }) => {
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
      ...(check ? { latest_version: 'v2.0.2' } : {}),
    } })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '关于' }).click()
  await page.getByRole('button', { name: '检查更新' }).click()
  await expect(page.getByText('版本检查完成')).toBeVisible()
  await expect(page.getByText('GitHub 最新版本：v2.0.2')).toBeVisible()
  await expect(page.getByText('请查看发布页获取更新')).toBeVisible()
  expect(checkCalls).toBe(1)
})

test('settings save posts Seoul region_id', async ({ page }) => {
  let saveCalls = 0
  let regionId = ''
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/config', async (route) => {
    if (route.request().method() === 'PUT') {
      saveCalls += 1
      const body = JSON.parse(route.request().postData() || '{}') as { accounts?: Record<string, unknown>[] }
      expectKnownKeys(body as Record<string, unknown>, CONFIG_OBJECT_KEYS)
      const account = body.accounts?.[0]
      if (account) expectKnownKeys(account, ACCOUNT_OBJECT_KEYS)
      regionId = String(account?.region_id || '')
      return route.fulfill({ json: { success: true } })
    }
    return route.fulfill({ json: dashboardConfig })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '实例', exact: true }).click()
  await page.getByRole('combobox', { name: '地域' }).click()
  await page.getByRole('combobox', { name: '地域' }).fill('首尔')
  await page.getByRole('option', { name: /韩国（首尔）.*ap-northeast-2/ }).click()
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.getByText('配置已安全保存')).toBeVisible()
  expect(saveCalls).toBe(1)
  expect(regionId).toBe('ap-northeast-2')
})

test('settings save posts the chosen timezone', async ({ page }) => {
  let saveCalls = 0
  let timezone = ''
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/config', async (route) => {
    if (route.request().method() === 'PUT') {
      saveCalls += 1
      const body = JSON.parse(route.request().postData() || '{}') as Record<string, unknown>
      expectKnownKeys(body, CONFIG_OBJECT_KEYS)
      timezone = String(body.timezone || '')
      return route.fulfill({ json: { success: true } })
    }
    return route.fulfill({ json: dashboardConfig })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByLabel('系统时区').fill('Asia/Taipei')
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.getByText('配置已安全保存')).toBeVisible()
  expect(saveCalls).toBe(1)
  expect(timezone).toBe('Asia/Taipei')
})

test('settings save posts custom traffic_threshold', async ({ page }) => {
  let saveCalls = 0
  let threshold: number | undefined
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/config', async (route) => {
    if (route.request().method() === 'PUT') {
      saveCalls += 1
      const body = JSON.parse(route.request().postData() || '{}') as Record<string, unknown>
      expectKnownKeys(body, CONFIG_OBJECT_KEYS)
      threshold = Number(body.traffic_threshold)
      return route.fulfill({ json: { success: true } })
    }
    return route.fulfill({ json: dashboardConfig })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByLabel('告警阈值').fill('80')
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.getByText('配置已安全保存')).toBeVisible()
  expect(saveCalls).toBe(1)
  expect(threshold).toBe(80)
})

test('settings save posts international site_type', async ({ page }) => {
  let saveCalls = 0
  let siteType = ''
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/config', async (route) => {
    if (route.request().method() === 'PUT') {
      saveCalls += 1
      const body = JSON.parse(route.request().postData() || '{}') as { accounts?: Record<string, unknown>[] }
      expectKnownKeys(body as Record<string, unknown>, CONFIG_OBJECT_KEYS)
      const account = body.accounts?.[0]
      if (account) expectKnownKeys(account, ACCOUNT_OBJECT_KEYS)
      siteType = String(account?.site_type || '')
      return route.fulfill({ json: { success: true } })
    }
    return route.fulfill({ json: dashboardConfig })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '实例', exact: true }).click()
  await page.getByRole('combobox', { name: '站点类型' }).click()
  await page.getByRole('option', { name: /国际站/ }).click()
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.getByText('配置已安全保存')).toBeVisible()
  expect(saveCalls).toBe(1)
  expect(siteType).toBe('international')
})

test('settings save posts schedule window', async ({ page }) => {
  let saveCalls = 0
  let account: Record<string, unknown> | undefined
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/config', async (route) => {
    if (route.request().method() === 'PUT') {
      saveCalls += 1
      const body = JSON.parse(route.request().postData() || '{}') as { accounts?: Record<string, unknown>[] }
      expectKnownKeys(body as Record<string, unknown>, CONFIG_OBJECT_KEYS)
      account = body.accounts?.[0]
      if (account) expectKnownKeys(account, ACCOUNT_OBJECT_KEYS)
      return route.fulfill({ json: { success: true } })
    }
    return route.fulfill({ json: dashboardConfig })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '实例', exact: true }).click()
  await page.getByText('每日定时开关机', { exact: true }).click()
  await page.getByLabel('开机时间').fill('09:00')
  await page.getByLabel('关机时间').fill('22:00')
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.getByText('配置已安全保存')).toBeVisible()
  expect(saveCalls).toBe(1)
  expect(account).toMatchObject({ schedule_enabled: true, start_time: '09:00', stop_time: '22:00' })
})

test('settings save posts custom max_traffic', async ({ page }) => {
  let saveCalls = 0
  let maxTraffic: number | undefined
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/config', async (route) => {
    if (route.request().method() === 'PUT') {
      saveCalls += 1
      const body = JSON.parse(route.request().postData() || '{}') as { accounts?: Record<string, unknown>[] }
      expectKnownKeys(body as Record<string, unknown>, CONFIG_OBJECT_KEYS)
      const account = body.accounts?.[0]
      if (account) expectKnownKeys(account, ACCOUNT_OBJECT_KEYS)
      maxTraffic = Number(account?.max_traffic)
      return route.fulfill({ json: { success: true } })
    }
    return route.fulfill({ json: dashboardConfig })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '实例', exact: true }).click()
  await page.getByLabel('流量额度').fill('350')
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.getByText('配置已安全保存')).toBeVisible()
  expect(saveCalls).toBe(1)
  expect(maxTraffic).toBe(350)
})

test('settings save posts a newly added account with documented fields', async ({ page }) => {
  let saveCalls = 0
  let added: Record<string, unknown> | undefined
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/config', async (route) => {
    if (route.request().method() === 'PUT') {
      saveCalls += 1
      const body = JSON.parse(route.request().postData() || '{}') as { accounts?: Record<string, unknown>[] }
      expectKnownKeys(body as Record<string, unknown>, CONFIG_OBJECT_KEYS)
      expect(body.accounts).toHaveLength(2)
      added = body.accounts?.[1]
      if (added) expectKnownKeys(added, ACCOUNT_OBJECT_KEYS)
      return route.fulfill({ json: { success: true } })
    }
    return route.fulfill({ json: dashboardConfig })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '实例', exact: true }).click()
  await page.getByRole('button', { name: '添加实例' }).click()
  await page.getByLabel('AccessKey ID').nth(1).fill('LTAI5added')
  await page.getByLabel('实例 ID').nth(1).fill('i-added')
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.getByText('配置已安全保存')).toBeVisible()
  expect(saveCalls).toBe(1)
  expect(added).toMatchObject({
    access_key_id: 'LTAI5added',
    instance_id: 'i-added',
    region_id: 'cn-hongkong',
    site_type: 'china',
    max_traffic: 200,
    secret_configured: false,
  })
})

test('settings save surfaces the live missing account secret envelope', async ({ page }) => {
  let saveCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/config', (route) => {
    if (route.request().method() === 'PUT') {
      saveCalls += 1
      const body = JSON.parse(route.request().postData() || '{}') as { accounts?: Record<string, unknown>[] }
      expect(body.accounts).toHaveLength(2)
      expect(body.accounts?.[1]).toMatchObject({ access_key_id: 'LTAI5added', secret_configured: false })
      expect(body.accounts?.[1]).not.toHaveProperty('access_key_secret')
      return route.fulfill({
        status: 400,
        json: { error: { code: 'config_failed', message: 'account LTAI5added is missing access key secret' } },
      })
    }
    return route.fulfill({ json: dashboardConfig })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '实例', exact: true }).click()
  await page.getByRole('button', { name: '添加实例' }).click()
  await page.getByLabel('AccessKey ID').nth(1).fill('LTAI5added')
  await page.getByLabel('实例 ID').nth(1).fill('i-added')
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: 'account LTAI5added is missing access key secret' }).first()).toBeVisible()
  expect(saveCalls).toBe(1)
})

test('settings save surfaces the live missing account identity envelope', async ({ page }) => {
  let saveCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/config', (route) => {
    if (route.request().method() === 'PUT') {
      saveCalls += 1
      const body = JSON.parse(route.request().postData() || '{}') as { accounts?: Record<string, unknown>[] }
      expect(body.accounts).toHaveLength(2)
      expect(body.accounts?.[1]).toMatchObject({ access_key_id: '', region_id: 'cn-hongkong' })
      return route.fulfill({
        status: 400,
        json: { error: { code: 'config_failed', message: 'account access_key_id and region_id are required' } },
      })
    }
    return route.fulfill({ json: dashboardConfig })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '实例', exact: true }).click()
  await page.getByRole('button', { name: '添加实例' }).click()
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: 'account access_key_id and region_id are required' }).first()).toBeVisible()
  expect(saveCalls).toBe(1)
})

test('settings save posts an empty accounts list after delete', async ({ page }) => {
  let saveCalls = 0
  let accounts: unknown
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/config', async (route) => {
    if (route.request().method() === 'PUT') {
      saveCalls += 1
      const body = JSON.parse(route.request().postData() || '{}') as { accounts?: unknown }
      expectKnownKeys(body as Record<string, unknown>, CONFIG_OBJECT_KEYS)
      accounts = body.accounts
      return route.fulfill({ json: { success: true } })
    }
    return route.fulfill({ json: dashboardConfig })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '实例', exact: true }).click()
  await page.getByRole('button', { name: '删除', exact: true }).click()
  await expect(page.getByText('尚未配置实例')).toBeVisible()
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.getByText('配置已安全保存')).toBeVisible()
  expect(saveCalls).toBe(1)
  expect(accounts).toEqual([])
})

test('settings save posts account remark and secret', async ({ page }) => {
  let saveCalls = 0
  let account: Record<string, unknown> | undefined
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/config', async (route) => {
    if (route.request().method() === 'PUT') {
      saveCalls += 1
      const body = JSON.parse(route.request().postData() || '{}') as { accounts?: Record<string, unknown>[] }
      expectKnownKeys(body as Record<string, unknown>, CONFIG_OBJECT_KEYS)
      account = body.accounts?.[0]
      if (account) expectKnownKeys(account, ACCOUNT_OBJECT_KEYS)
      return route.fulfill({ json: { success: true } })
    }
    return route.fulfill({ json: dashboardConfig })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '实例', exact: true }).click()
  await page.getByLabel(/AccessKey Secret/).fill('fixture-secret-not-real')
  await page.getByLabel('备注').fill('首尔备用节点')
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.getByText('配置已安全保存')).toBeVisible()
  expect(saveCalls).toBe(1)
  expect(account).toMatchObject({
    access_key_secret: 'fixture-secret-not-real',
    remark: '首尔备用节点',
    secret_configured: true,
  })
})

test('settings save posts account identity fields', async ({ page }) => {
  let saveCalls = 0
  let account: Record<string, unknown> | undefined
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/config', async (route) => {
    if (route.request().method() === 'PUT') {
      saveCalls += 1
      const body = JSON.parse(route.request().postData() || '{}') as { accounts?: Record<string, unknown>[] }
      expectKnownKeys(body as Record<string, unknown>, CONFIG_OBJECT_KEYS)
      account = body.accounts?.[0]
      if (account) expectKnownKeys(account, ACCOUNT_OBJECT_KEYS)
      return route.fulfill({ json: { success: true } })
    }
    return route.fulfill({ json: dashboardConfig })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '实例', exact: true }).click()
  await page.getByLabel('AccessKey ID').fill('LTAI5settings')
  await page.getByLabel('实例 ID').fill('i-settings')
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.getByText('配置已安全保存')).toBeVisible()
  expect(saveCalls).toBe(1)
  expect(account).toMatchObject({
    access_key_id: 'LTAI5settings',
    instance_id: 'i-settings',
  })
})

test('about update check shows current version as latest', async ({ page }) => {
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
      ...(check ? { latest_version: 'v2.0.1' } : {}),
    } })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '关于' }).click()
  await page.getByRole('button', { name: '检查更新' }).click()
  await expect(page.getByText('版本检查完成')).toBeVisible()
  await expect(page.getByText('GitHub 最新版本：v2.0.1')).toBeVisible()
  await expect(page.getByText('当前已是最新版本')).toBeVisible()
  expect(checkCalls).toBe(1)
})

test('settings save posts hourly api_interval', async ({ page }) => {
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
  await page.getByRole('option', { name: '1 小时' }).click()
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.getByText('配置已安全保存')).toBeVisible()
  expect(saveCalls).toBe(1)
  expect(interval).toBe(3600)
})

test('settings logs treat a null logs array as empty', async ({ page }) => {
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/logs**', (route) => {
    expect(route.request().method()).toBe('GET')
    expect(new URL(route.request().url()).searchParams.get('tab')).toBe('action')
    return route.fulfill({ json: { logs: null } })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '日志' }).click()
  await expect(page.getByText('暂无日志')).toBeVisible()
  await expect(page.getByRole('heading', { name: '运行日志' })).toBeVisible()
})

test('settings webhook get json posts the live webhook contract', async ({ page }) => {
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
  await page.getByLabel('Body 模板').fill('{"title":"#TITLE#","message":"#MSG#"}')
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.getByText('配置已安全保存')).toBeVisible()
  expect(savedWebhook).toMatchObject({
    enabled: true,
    url: 'https://example.invalid/hook',
    method: 'GET',
    request_type: 'JSON',
    body: '{"title":"#TITLE#","message":"#MSG#"}',
    secret_configured: false,
  })
})

test('settings API keys treat null scopes as unconfigured', async ({ page }) => {
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/api-keys', (route) => route.fulfill({ json: { keys: [{
    id: 9,
    name: '旧版 Key',
    scopes: null,
    created_at: new Date().toISOString(),
  }] } }))

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: 'API Key' }).click()
  await expect(page.locator('.key-row')).toContainText('旧版 Key')
  await expect(page.locator('.key-row')).toContainText('未配置权限')
})

test('settings API keys show last_used_at from the live key contract', async ({ page }) => {
  const at = '2026-09-07T16:00:00.000Z'
  await mockInitStatus(page, true)
  await mockDashboardReads(page, dashboardStatus, { ...dashboardConfig, timezone: 'Asia/Shanghai' })
  await page.route('**/api/v1/api-keys', (route) => route.fulfill({ json: { keys: [{
    id: 4,
    name: '桌面小组件',
    scopes: ['widget:read'],
    created_at: at,
    last_used_at: at,
  }] } }))

  await page.goto('/')
  const expected = await page.evaluate(
    (timestamp) => new Date(timestamp).toLocaleString('zh-CN', { month: 'numeric', day: 'numeric', hour: '2-digit', minute: '2-digit', hour12: false, timeZone: 'Asia/Shanghai' }),
    at,
  )
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: 'API Key' }).click()
  await expect(page.locator('.key-row time')).toHaveText(`最近使用 ${expected}`)
})

test('admin passkeys show last_used_at from the live passkey contract', async ({ page }) => {
  const at = '2026-09-07T16:00:00.000Z'
  await mockInitStatus(page, true)
  await mockDashboardReads(page, dashboardStatus, { ...dashboardConfig, timezone: 'Asia/Shanghai' })
  await page.route('**/api/v1/admin/passkeys', (route) => route.fulfill({ json: { passkeys: [{
    id: 6,
    name: '办公室电脑',
    created_at: at,
    last_used_at: at,
  }] } }))

  await page.goto('/')
  const expected = await page.evaluate(
    (timestamp) => new Date(timestamp).toLocaleString('zh-CN', { month: 'numeric', day: 'numeric', hour: '2-digit', minute: '2-digit', hour12: false, timeZone: 'Asia/Shanghai' }),
    at,
  )
  await page.getByRole('button', { name: '管理员' }).click()
  await expect(page.locator('.passkey-row')).toContainText('办公室电脑')
  await expect(page.locator('.passkey-row')).toContainText(`最近使用 ${expected}`)
})

test('settings API keys hide revoked keys from the live list contract', async ({ page }) => {
  const at = new Date().toISOString()
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/api-keys', (route) => route.fulfill({ json: { keys: [
    { id: 1, name: '已撤销 Key', scopes: ['widget:read'], created_at: at, revoked_at: at },
    { id: 2, name: '桌面小组件', scopes: ['widget:read'], created_at: at },
  ] } }))

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: 'API Key' }).click()
  await expect(page.locator('.key-row')).toHaveCount(1)
  await expect(page.locator('.key-row')).toContainText('桌面小组件')
  await expect(page.getByText('已撤销 Key')).toHaveCount(0)
})

test('settings API keys treat a null keys array as empty', async ({ page }) => {
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/api-keys', (route) => route.fulfill({ json: { keys: null } }))

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: 'API Key' }).click()
  await expect(page.getByRole('button', { name: '创建 Key' })).toBeVisible()
  await expect(page.locator('.key-row')).toHaveCount(0)
})

test('settings webhook omits empty headers from the live notify contract', async ({ page }) => {
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
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.getByText('配置已安全保存')).toBeVisible()
  expect(savedWebhook).toMatchObject({
    enabled: true,
    url: 'https://example.invalid/hook',
    method: 'GET',
    request_type: 'JSON',
    secret_configured: false,
  })
  expect(savedWebhook).not.toHaveProperty('headers')
})

test('settings webhook keeps configured url when left empty', async ({ page }) => {
  const configured = {
    ...dashboardConfig,
    notifications: {
      ...dashboardConfig.notifications,
      webhook: liveGetWebhook({
        enabled: true,
        method: 'POST',
        request_type: 'JSON',
        url_configured: true,
      }),
    },
  }
  let savedWebhook: Record<string, unknown> | undefined
  await mockInitStatus(page, true)
  await mockDashboardReads(page, dashboardStatus, configured)
  await page.route('**/api/v1/config', async (route) => {
    if (route.request().method() === 'PUT') {
      const payload = JSON.parse(route.request().postData() || '{}') as { notifications?: { webhook?: Record<string, unknown> } }
      expectKnownKeys(payload, CONFIG_OBJECT_KEYS)
      savedWebhook = payload.notifications?.webhook
      return route.fulfill({ json: { success: true } })
    }
    return route.fulfill({ json: configured })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: 'Webhook' }).click()
  const urlField = page.getByLabel('Webhook URL · 已配置')
  await expect(urlField).toBeVisible()
  await expect(urlField).toHaveAttribute('placeholder', '留空保持不变')
  await expect(urlField).toHaveValue('')
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.getByText('配置已安全保存')).toBeVisible()
  expect(savedWebhook).toMatchObject({
    enabled: true,
    url_configured: true,
  })
  expect(savedWebhook).not.toHaveProperty('url')
  expect(JSON.stringify(savedWebhook)).not.toContain('__clear__')
})

test('settings webhook clears configured url with the live sentinel', async ({ page }) => {
  const configured = {
    ...dashboardConfig,
    notifications: {
      ...dashboardConfig.notifications,
      webhook: liveGetWebhook({
        enabled: true,
        method: 'POST',
        request_type: 'JSON',
        url_configured: true,
      }),
    },
  }
  let savedWebhook: Record<string, unknown> | undefined
  await mockInitStatus(page, true)
  await mockDashboardReads(page, dashboardStatus, configured)
  await page.route('**/api/v1/config', async (route) => {
    if (route.request().method() === 'PUT') {
      const payload = JSON.parse(route.request().postData() || '{}') as { notifications?: { webhook?: Record<string, unknown> } }
      expectKnownKeys(payload, CONFIG_OBJECT_KEYS)
      savedWebhook = payload.notifications?.webhook
      return route.fulfill({ json: { success: true } })
    }
    return route.fulfill({ json: configured })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: 'Webhook' }).click()
  const urlField = page.getByLabel('Webhook URL · 已配置')
  await expect(urlField).toHaveValue('')
  await expect(page.getByText('__clear__')).toHaveCount(0)
  await page.getByText('清除已配置的 URL', { exact: true }).click()
  await expect(urlField).toHaveAttribute('placeholder', '保存后清除')
  await expect(urlField).toHaveValue('')
  await expect(page.getByText('__clear__')).toHaveCount(0)
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.getByText('配置已安全保存')).toBeVisible()
  expect(savedWebhook).toMatchObject({
    enabled: true,
    url: '__clear__',
    url_configured: true,
  })
})

test('settings webhook keeps configured body when left empty', async ({ page }) => {
  const configured = {
    ...dashboardConfig,
    notifications: {
      ...dashboardConfig.notifications,
      webhook: liveGetWebhook({
        enabled: true,
        method: 'POST',
        request_type: 'JSON',
        body_configured: true,
      }),
    },
  }
  let savedWebhook: Record<string, unknown> | undefined
  await mockInitStatus(page, true)
  await mockDashboardReads(page, dashboardStatus, configured)
  await page.route('**/api/v1/config', async (route) => {
    if (route.request().method() === 'PUT') {
      const payload = JSON.parse(route.request().postData() || '{}') as { notifications?: { webhook?: Record<string, unknown> } }
      expectKnownKeys(payload, CONFIG_OBJECT_KEYS)
      savedWebhook = payload.notifications?.webhook
      return route.fulfill({ json: { success: true } })
    }
    return route.fulfill({ json: configured })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: 'Webhook' }).click()
  const bodyField = page.getByLabel('Body 模板 · 已配置')
  await expect(bodyField).toBeVisible()
  await expect(bodyField).toHaveAttribute('placeholder', '留空保持不变')
  await expect(bodyField).toHaveValue('')
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.getByText('配置已安全保存')).toBeVisible()
  expect(savedWebhook).toMatchObject({
    enabled: true,
    body_configured: true,
  })
  expect(savedWebhook).not.toHaveProperty('body')
  expect(JSON.stringify(savedWebhook)).not.toContain('__clear__')
})

test('settings webhook clears configured body with the live sentinel', async ({ page }) => {
  const configured = {
    ...dashboardConfig,
    notifications: {
      ...dashboardConfig.notifications,
      webhook: liveGetWebhook({
        enabled: true,
        method: 'POST',
        request_type: 'JSON',
        body_configured: true,
      }),
    },
  }
  let savedWebhook: Record<string, unknown> | undefined
  await mockInitStatus(page, true)
  await mockDashboardReads(page, dashboardStatus, configured)
  await page.route('**/api/v1/config', async (route) => {
    if (route.request().method() === 'PUT') {
      const payload = JSON.parse(route.request().postData() || '{}') as { notifications?: { webhook?: Record<string, unknown> } }
      expectKnownKeys(payload, CONFIG_OBJECT_KEYS)
      savedWebhook = payload.notifications?.webhook
      return route.fulfill({ json: { success: true } })
    }
    return route.fulfill({ json: configured })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: 'Webhook' }).click()
  const bodyField = page.getByLabel('Body 模板 · 已配置')
  await expect(bodyField).toHaveValue('')
  await expect(page.getByText('__clear__')).toHaveCount(0)
  await page.getByText('清除已配置的 Body', { exact: true }).click()
  await expect(bodyField).toHaveAttribute('placeholder', '保存后清除')
  await expect(bodyField).toHaveValue('')
  await expect(page.getByText('__clear__')).toHaveCount(0)
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.getByText('配置已安全保存')).toBeVisible()
  expect(savedWebhook).toMatchObject({
    enabled: true,
    body: '__clear__',
    body_configured: true,
  })
})

test('settings webhook keeps configured headers when left empty', async ({ page }) => {
  const configured = {
    ...dashboardConfig,
    notifications: {
      ...dashboardConfig.notifications,
      webhook: {
        ...liveGetWebhook({
          enabled: true,
          method: 'POST',
          request_type: 'JSON',
          headers_configured: true,
        }),
      },
    },
  }
  let savedWebhook: Record<string, unknown> | undefined
  await mockInitStatus(page, true)
  await mockDashboardReads(page, dashboardStatus, configured)
  await page.route('**/api/v1/config', async (route) => {
    if (route.request().method() === 'PUT') {
      const payload = JSON.parse(route.request().postData() || '{}') as { notifications?: { webhook?: Record<string, unknown> } }
      expectKnownKeys(payload, CONFIG_OBJECT_KEYS)
      savedWebhook = payload.notifications?.webhook
      return route.fulfill({ json: { success: true } })
    }
    return route.fulfill({ json: configured })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: 'Webhook' }).click()
  const headersField = page.getByLabel('自定义 Headers · 已配置')
  await expect(headersField).toBeVisible()
  await expect(headersField).toHaveAttribute('placeholder', '留空保持不变')
  await expect(headersField).toHaveValue('')
  await expect(page.getByLabel('Webhook URL')).toHaveValue('')
  await expect(page.getByText('example.invalid')).toHaveCount(0)
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.getByText('配置已安全保存')).toBeVisible()
  expect(savedWebhook).toMatchObject({
    enabled: true,
    method: 'POST',
    request_type: 'JSON',
    headers_configured: true,
    url_configured: false,
    body_configured: false,
  })
  expect(savedWebhook).not.toHaveProperty('headers')
  expect(savedWebhook).not.toHaveProperty('url')
  expect(JSON.stringify(savedWebhook)).not.toContain('__clear__')
  expect(JSON.stringify(savedWebhook)).not.toContain('example.invalid')
})

test('settings webhook clears configured headers with the live sentinel', async ({ page }) => {
  const configured = {
    ...dashboardConfig,
    notifications: {
      ...dashboardConfig.notifications,
      webhook: {
        ...liveGetWebhook({
          enabled: true,
          method: 'POST',
          request_type: 'JSON',
          headers_configured: true,
        }),
      },
    },
  }
  let savedWebhook: Record<string, unknown> | undefined
  await mockInitStatus(page, true)
  await mockDashboardReads(page, dashboardStatus, configured)
  await page.route('**/api/v1/config', async (route) => {
    if (route.request().method() === 'PUT') {
      const payload = JSON.parse(route.request().postData() || '{}') as { notifications?: { webhook?: Record<string, unknown> } }
      expectKnownKeys(payload, CONFIG_OBJECT_KEYS)
      savedWebhook = payload.notifications?.webhook
      return route.fulfill({ json: { success: true } })
    }
    return route.fulfill({ json: configured })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: 'Webhook' }).click()
  const headersField = page.getByLabel('自定义 Headers · 已配置')
  await expect(headersField).toHaveValue('')
  await expect(page.getByLabel('Webhook URL')).toHaveValue('')
  await expect(page.getByText('example.invalid')).toHaveCount(0)
  await expect(page.getByText('__clear__')).toHaveCount(0)
  await page.getByText('清除已配置的 Headers', { exact: true }).click()
  await expect(headersField).toHaveAttribute('placeholder', '保存后清除')
  await expect(headersField).toHaveValue('')
  await expect(page.getByText('__clear__')).toHaveCount(0)
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.getByText('配置已安全保存')).toBeVisible()
  expect(savedWebhook).toMatchObject({
    enabled: true,
    headers: '__clear__',
    headers_configured: true,
    url_configured: false,
    body_configured: false,
  })
  expect(savedWebhook).not.toHaveProperty('url')
  expect(JSON.stringify(savedWebhook)).not.toContain('example.invalid')
})

test('settings email omits empty password from the live notify contract', async ({ page }) => {
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
  await page.getByLabel('用户名').fill('ops')
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.getByText('配置已安全保存')).toBeVisible()
  expect(savedEmail).toMatchObject({
    enabled: true,
    to: 'ops@example.invalid',
    host: 'smtp.example.invalid',
    username: 'ops',
    password_configured: false,
  })
  expect(savedEmail).not.toHaveProperty('password')
})

test('settings email keeps configured password when left empty', async ({ page }) => {
  const configured = {
    ...dashboardConfig,
    notifications: {
      ...dashboardConfig.notifications,
      email: liveGetEmail({
        enabled: true,
        to: 'ops@example.invalid',
        host: 'smtp.example.invalid',
        port: 465,
        username: 'ops',
        password_configured: true,
        security: 'ssl',
      }),
    },
  }
  let savedEmail: Record<string, unknown> | undefined
  await mockInitStatus(page, true)
  await mockDashboardReads(page, dashboardStatus, configured)
  await page.route('**/api/v1/config', async (route) => {
    if (route.request().method() === 'PUT') {
      const payload = JSON.parse(route.request().postData() || '{}') as { notifications?: { email?: Record<string, unknown> } }
      expectKnownKeys(payload, CONFIG_OBJECT_KEYS)
      savedEmail = payload.notifications?.email
      return route.fulfill({ json: { success: true } })
    }
    return route.fulfill({ json: configured })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  const passwordField = page.getByLabel('密码 · 已配置')
  await expect(passwordField).toBeVisible()
  await expect(passwordField).toHaveAttribute('placeholder', '留空保持不变')
  await expect(passwordField).toHaveValue('')
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.getByText('配置已安全保存')).toBeVisible()
  expect(savedEmail).toMatchObject({
    enabled: true,
    to: 'ops@example.invalid',
    password_configured: true,
  })
  expect(savedEmail).not.toHaveProperty('password')
  expect(JSON.stringify(savedEmail)).not.toContain('__clear__')
})

test('settings email clears configured password with the live sentinel', async ({ page }) => {
  const configured = {
    ...dashboardConfig,
    notifications: {
      ...dashboardConfig.notifications,
      email: liveGetEmail({
        enabled: true,
        to: 'ops@example.invalid',
        host: 'smtp.example.invalid',
        port: 465,
        username: 'ops',
        password_configured: true,
        security: 'ssl',
      }),
    },
  }
  let savedEmail: Record<string, unknown> | undefined
  await mockInitStatus(page, true)
  await mockDashboardReads(page, dashboardStatus, configured)
  await page.route('**/api/v1/config', async (route) => {
    if (route.request().method() === 'PUT') {
      const payload = JSON.parse(route.request().postData() || '{}') as { notifications?: { email?: Record<string, unknown> } }
      expectKnownKeys(payload, CONFIG_OBJECT_KEYS)
      savedEmail = payload.notifications?.email
      return route.fulfill({ json: { success: true } })
    }
    return route.fulfill({ json: configured })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  const passwordField = page.getByLabel('密码 · 已配置')
  await expect(passwordField).toHaveValue('')
  await expect(page.getByText('__clear__')).toHaveCount(0)
  await page.getByText('清除已配置的密码', { exact: true }).click()
  await expect(passwordField).toHaveAttribute('placeholder', '保存后清除')
  await expect(passwordField).toHaveValue('')
  await expect(page.getByText('__clear__')).toHaveCount(0)
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.getByText('配置已安全保存')).toBeVisible()
  expect(savedEmail).toMatchObject({
    enabled: true,
    to: 'ops@example.invalid',
    password: '__clear__',
    password_configured: true,
  })
})

test('settings telegram omits empty token from the live notify contract', async ({ page }) => {
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
  await page.getByLabel('Chat ID').fill('-1001')
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.getByText('配置已安全保存')).toBeVisible()
  expect(savedTelegram).toMatchObject({
    enabled: true,
    token_configured: false,
    chat_id: '-1001',
    proxy_type: 'none',
    proxy_password_configured: false,
  })
  expect(savedTelegram).not.toHaveProperty('token')
  expect(savedTelegram).not.toHaveProperty('proxy_pass')
})

test('settings telegram keeps configured token when left empty', async ({ page }) => {
  const configured = {
    ...dashboardConfig,
    notifications: {
      ...dashboardConfig.notifications,
      telegram: liveGetTelegram({
        enabled: true,
        token_configured: true,
        chat_id: '-1001',
        proxy_type: 'none',
      }),
    },
  }
  let savedTelegram: Record<string, unknown> | undefined
  await mockInitStatus(page, true)
  await mockDashboardReads(page, dashboardStatus, configured)
  await page.route('**/api/v1/config', async (route) => {
    if (route.request().method() === 'PUT') {
      const payload = JSON.parse(route.request().postData() || '{}') as { notifications?: { telegram?: Record<string, unknown> } }
      expectKnownKeys(payload, CONFIG_OBJECT_KEYS)
      savedTelegram = payload.notifications?.telegram
      return route.fulfill({ json: { success: true } })
    }
    return route.fulfill({ json: configured })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: 'Telegram' }).click()
  const tokenField = page.getByLabel('Bot Token · 已配置')
  await expect(tokenField).toBeVisible()
  await expect(tokenField).toHaveAttribute('placeholder', '留空保持不变')
  await expect(tokenField).toHaveValue('')
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.getByText('配置已安全保存')).toBeVisible()
  expect(savedTelegram).toMatchObject({
    enabled: true,
    chat_id: '-1001',
    token_configured: true,
  })
  expect(savedTelegram).not.toHaveProperty('token')
  expect(JSON.stringify(savedTelegram)).not.toContain('__clear__')
})

test('settings telegram clears configured token with the live sentinel', async ({ page }) => {
  const configured = {
    ...dashboardConfig,
    notifications: {
      ...dashboardConfig.notifications,
      telegram: liveGetTelegram({
        enabled: true,
        token_configured: true,
        chat_id: '-1001',
        proxy_type: 'none',
      }),
    },
  }
  let savedTelegram: Record<string, unknown> | undefined
  await mockInitStatus(page, true)
  await mockDashboardReads(page, dashboardStatus, configured)
  await page.route('**/api/v1/config', async (route) => {
    if (route.request().method() === 'PUT') {
      const payload = JSON.parse(route.request().postData() || '{}') as { notifications?: { telegram?: Record<string, unknown> } }
      expectKnownKeys(payload, CONFIG_OBJECT_KEYS)
      savedTelegram = payload.notifications?.telegram
      return route.fulfill({ json: { success: true } })
    }
    return route.fulfill({ json: configured })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: 'Telegram' }).click()
  const tokenField = page.getByLabel('Bot Token · 已配置')
  await expect(tokenField).toHaveValue('')
  await expect(page.getByText('__clear__')).toHaveCount(0)
  await page.getByText('清除已配置的 Bot Token', { exact: true }).click()
  await expect(tokenField).toHaveAttribute('placeholder', '保存后清除')
  await expect(tokenField).toHaveValue('')
  await expect(page.getByText('__clear__')).toHaveCount(0)
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.getByText('配置已安全保存')).toBeVisible()
  expect(savedTelegram).toMatchObject({
    enabled: true,
    chat_id: '-1001',
    token: '__clear__',
    token_configured: true,
  })
})

test('settings save omits unchanged account secret', async ({ page }) => {
  let saveCalls = 0
  let account: Record<string, unknown> | undefined
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/config', async (route) => {
    if (route.request().method() === 'PUT') {
      saveCalls += 1
      const body = JSON.parse(route.request().postData() || '{}') as { accounts?: Record<string, unknown>[] }
      expectKnownKeys(body as Record<string, unknown>, CONFIG_OBJECT_KEYS)
      account = body.accounts?.[0]
      if (account) expectKnownKeys(account, ACCOUNT_OBJECT_KEYS)
      return route.fulfill({ json: { success: true } })
    }
    return route.fulfill({ json: dashboardConfig })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '实例', exact: true }).click()
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.getByText('配置已安全保存')).toBeVisible()
  expect(saveCalls).toBe(1)
  expect(account).toMatchObject({
    access_key_id: 'LTAI5test',
    secret_configured: true,
    instance_id: 'i-test',
  })
  expect(account).not.toHaveProperty('access_key_secret')
})

test('settings webhook omits empty secret from the live notify contract', async ({ page }) => {
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
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.getByText('配置已安全保存')).toBeVisible()
  expect(savedWebhook).toMatchObject({
    enabled: true,
    url: 'https://example.invalid/hook',
    secret_configured: false,
  })
  expect(savedWebhook).not.toHaveProperty('secret')
})

test('settings webhook keeps configured dingtalk secret when left empty', async ({ page }) => {
  const configured = {
    ...dashboardConfig,
    notifications: {
      ...dashboardConfig.notifications,
      webhook: {
        ...liveGetWebhook({
          enabled: true,
          method: 'POST',
          request_type: 'JSON',
          provider: 'dingtalk',
          secret_configured: true,
          url_configured: true,
        }),
      },
    },
  }
  let savedWebhook: Record<string, unknown> | undefined
  await mockInitStatus(page, true)
  await mockDashboardReads(page, dashboardStatus, configured)
  await page.route('**/api/v1/config', async (route) => {
    if (route.request().method() === 'PUT') {
      const payload = JSON.parse(route.request().postData() || '{}') as { notifications?: { webhook?: Record<string, unknown> } }
      expectKnownKeys(payload, CONFIG_OBJECT_KEYS)
      savedWebhook = payload.notifications?.webhook
      return route.fulfill({ json: { success: true } })
    }
    return route.fulfill({ json: configured })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: 'Webhook' }).click()
  const secretField = page.getByLabel('钉钉加签密钥 · 已配置')
  await expect(secretField).toBeVisible()
  await expect(secretField).toHaveAttribute('placeholder', '留空保持不变')
  await expect(secretField).toHaveValue('')
  await expect(page.getByLabel('Webhook URL · 已配置')).toHaveValue('')
  await expect(page.getByText('ding-token')).toHaveCount(0)
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.getByText('配置已安全保存')).toBeVisible()
  expect(savedWebhook).toMatchObject({
    enabled: true,
    provider: 'dingtalk',
    secret_configured: true,
    url_configured: true,
  })
  expect(savedWebhook).not.toHaveProperty('secret')
  expect(savedWebhook).not.toHaveProperty('url')
  expect(JSON.stringify(savedWebhook)).not.toContain('__clear__')
  expect(JSON.stringify(savedWebhook)).not.toContain('ding-token')
})

test('settings webhook clears configured dingtalk secret with the live sentinel', async ({ page }) => {
  const configured = {
    ...dashboardConfig,
    notifications: {
      ...dashboardConfig.notifications,
      webhook: {
        ...liveGetWebhook({
          enabled: true,
          method: 'POST',
          request_type: 'JSON',
          provider: 'dingtalk',
          secret_configured: true,
          url_configured: true,
        }),
      },
    },
  }
  let savedWebhook: Record<string, unknown> | undefined
  await mockInitStatus(page, true)
  await mockDashboardReads(page, dashboardStatus, configured)
  await page.route('**/api/v1/config', async (route) => {
    if (route.request().method() === 'PUT') {
      const payload = JSON.parse(route.request().postData() || '{}') as { notifications?: { webhook?: Record<string, unknown> } }
      expectKnownKeys(payload, CONFIG_OBJECT_KEYS)
      savedWebhook = payload.notifications?.webhook
      return route.fulfill({ json: { success: true } })
    }
    return route.fulfill({ json: configured })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: 'Webhook' }).click()
  const secretField = page.getByLabel('钉钉加签密钥 · 已配置')
  await expect(secretField).toHaveValue('')
  await expect(page.getByLabel('Webhook URL · 已配置')).toHaveValue('')
  await expect(page.getByText('ding-token')).toHaveCount(0)
  await expect(page.getByText('__clear__')).toHaveCount(0)
  await page.getByText('清除已配置的加签密钥', { exact: true }).click()
  await expect(secretField).toHaveAttribute('placeholder', '保存后清除')
  await expect(secretField).toHaveValue('')
  await expect(page.getByText('__clear__')).toHaveCount(0)
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.getByText('配置已安全保存')).toBeVisible()
  expect(savedWebhook).toMatchObject({
    enabled: true,
    provider: 'dingtalk',
    secret: '__clear__',
    secret_configured: true,
    url_configured: true,
  })
  expect(savedWebhook).not.toHaveProperty('url')
  expect(JSON.stringify(savedWebhook)).not.toContain('ding-token')
})

test('settings webhook keeps the live default generic provider', async ({ page }) => {
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
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.getByText('配置已安全保存')).toBeVisible()
  expect(savedWebhook).toMatchObject({
    enabled: true,
    url: 'https://example.invalid/hook',
    provider: 'generic',
  })
})

test('history chart treats a null hourly array as empty', async ({ page }) => {
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/accounts/1/history', (route) => route.fulfill({ json: {
    hourly: null,
    daily: [],
  } }))

  await page.goto('/')
  await page.getByRole('button', { name: '查看历史流量' }).click()
  await expect(page.getByText('等待采样数据')).toBeVisible()
  await expect(page.locator('.chart-area .recharts-wrapper')).toHaveCount(0)
})

test('history chart treats a null daily array as empty', async ({ page }) => {
  const hourStart = Math.floor(Date.now() / 3_600_000) * 3_600_000
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/accounts/1/history', (route) => route.fulfill({ json: {
    hourly: [{ at: new Date(hourStart).toISOString(), traffic: 1.25 }],
    daily: null,
  } }))

  await page.goto('/')
  await page.getByRole('button', { name: '查看历史流量' }).click()
  await expect(page.locator('.chart-area .recharts-wrapper')).toBeVisible()
  await page.getByRole('button', { name: '30 天' }).click()
  await expect(page.getByText('等待采样数据')).toBeVisible()
  await expect(page.locator('.chart-area .recharts-wrapper')).toHaveCount(0)
})

test('refresh-all with no jobs shows the live empty-queue message', async ({ page }) => {
  let refreshCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/accounts/refresh', (route) => {
    refreshCalls += 1
    expect(route.request().method()).toBe('POST')
    return route.fulfill({ status: 202, json: { jobs: [] } })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '强制刷新全部实例' }).click()
  await expect(page.getByText('暂无可刷新的实例')).toBeVisible()
  expect(refreshCalls).toBe(1)
})

test('refresh-all treats a null jobs array as empty', async ({ page }) => {
  let refreshCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/accounts/refresh', (route) => {
    refreshCalls += 1
    expect(route.request().method()).toBe('POST')
    return route.fulfill({ status: 202, json: { jobs: null } })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '强制刷新全部实例' }).click()
  await expect(page.getByText('暂无可刷新的实例')).toBeVisible()
  expect(refreshCalls).toBe(1)
})

test('refresh-all surfaces all-failed instance refresh', async ({ page }) => {
  let refreshCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/accounts/refresh', (route) => {
    refreshCalls += 1
    expect(route.request().method()).toBe('POST')
    return route.fulfill({ status: 202, json: { jobs: [jobFixture('refresh-a', 'queued'), jobFixture('refresh-b', 'queued')] } })
  })
  const leaked = 'FIXTURE-SECRET-TOKEN'
  await page.route('**/api/v1/jobs/**', (route) => {
    const id = route.request().url().split('/').pop() || 'refresh-a'
    const failed = jobFixture(id, 'failed')
    failed.error = `aliyun HTTP 403: AccessKeyId=${leaked}`
    return route.fulfill({ json: failed })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '强制刷新全部实例' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '全部实例刷新失败，请查看运行日志' }).first()).toBeVisible()
  await expect(page.locator('.toast-stack')).not.toContainText(leaked)
  expect(refreshCalls).toBe(1)
})

test('refresh-all timeout surfaces the all-failed refresh message', async ({ page }) => {
  await page.clock.install()
  let refreshCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/accounts/refresh', (route) => {
    refreshCalls += 1
    expect(route.request().method()).toBe('POST')
    return route.fulfill({ status: 202, json: { jobs: [jobFixture('refresh-timeout-a', 'queued'), jobFixture('refresh-timeout-b', 'queued')] } })
  })
  await page.route('**/api/v1/jobs/**', (route) => {
    const id = route.request().url().split('/').pop() || 'refresh-timeout-a'
    const queued = jobFixture(id, 'queued')
    queued.error = 'FIXTURE-SECRET-TOKEN'
    return route.fulfill({ json: queued })
  })

  await page.goto('/')
  const jobPolled = page.waitForRequest('**/api/v1/jobs/**')
  await page.getByRole('button', { name: '强制刷新全部实例' }).click()
  await jobPolled
  await page.clock.fastForward(71_000)
  await expect(page.locator('.toast--error').filter({ hasText: '全部实例刷新失败，请查看运行日志' }).first()).toBeVisible()
  await expect(page.locator('.toast-stack')).not.toContainText('FIXTURE-SECRET-TOKEN')
  expect(refreshCalls).toBe(1)
})

test('refresh-all surfaces partial instance refresh failure', async ({ page }) => {
  let refreshCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/accounts/refresh', (route) => {
    refreshCalls += 1
    expect(route.request().method()).toBe('POST')
    return route.fulfill({ status: 202, json: { jobs: [jobFixture('refresh-ok', 'queued'), jobFixture('refresh-bad', 'queued')] } })
  })
  const leaked = 'FIXTURE-SECRET-TOKEN'
  await page.route('**/api/v1/jobs/**', (route) => {
    const id = route.request().url().split('/').pop() || 'refresh-ok'
    if (id === 'refresh-bad') {
      const failed = jobFixture(id, 'failed')
      failed.error = `aliyun HTTP 403: AccessKeyId=${leaked}`
      return route.fulfill({ json: failed })
    }
    return route.fulfill({ json: jobFixture(id, 'completed') })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '强制刷新全部实例' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '已刷新 1/2 个实例，其余实例刷新失败' }).first()).toBeVisible()
  await expect(page.locator('.toast-stack')).not.toContainText(leaked)
  expect(refreshCalls).toBe(1)
})

test('refresh-all reports completion for every queued instance', async ({ page }) => {
  let refreshCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/accounts/refresh', (route) => {
    refreshCalls += 1
    expect(route.request().method()).toBe('POST')
    return route.fulfill({ status: 202, json: { jobs: [jobFixture('refresh-1', 'queued'), jobFixture('refresh-2', 'queued')] } })
  })
  await page.route('**/api/v1/jobs/**', (route) => {
    const id = route.request().url().split('/').pop() || 'refresh-1'
    return route.fulfill({ json: jobFixture(id, 'completed') })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '强制刷新全部实例' }).click()
  await expect(page.getByText('已强制刷新 2 个实例')).toBeVisible()
  expect(refreshCalls).toBe(1)
})

test('refresh-all ignores a second click while jobs are in flight', async ({ page }) => {
  let refreshCalls = 0
  let releaseJob!: (value?: unknown) => void
  const jobReady = new Promise((resolve) => { releaseJob = resolve })
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/accounts/refresh', (route) => {
    refreshCalls += 1
    expect(route.request().method()).toBe('POST')
    return route.fulfill({ status: 202, json: { jobs: [jobFixture('refresh-busy', 'queued')] } })
  })
  await page.route('**/api/v1/jobs/**', async (route) => {
    await jobReady
    return route.fulfill({ json: jobFixture('refresh-busy', 'completed') })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '强制刷新全部实例' }).click()
  await expect(page.getByRole('button', { name: '正在强制刷新全部实例' })).toBeDisabled()
  await expect(page.getByRole('button', { name: '刷新实例' })).toBeDisabled()
  await page.getByRole('button', { name: '正在强制刷新全部实例' }).click({ force: true })
  releaseJob()
  await expect(page.getByText('已强制刷新 1 个实例')).toBeVisible()
  expect(refreshCalls).toBe(1)
})

test('instance refresh disables power controls while the job is in flight', async ({ page }) => {
  let refreshCalls = 0
  let releaseJob!: (value?: unknown) => void
  const jobReady = new Promise((resolve) => { releaseJob = resolve })
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/accounts/1/refresh', (route) => {
    refreshCalls += 1
    expect(route.request().method()).toBe('POST')
    return route.fulfill({ status: 202, json: jobFixture('refresh-busy', 'queued', 1) })
  })
  await page.route('**/api/v1/jobs/**', async (route) => {
    await jobReady
    return route.fulfill({ json: jobFixture('refresh-busy', 'completed', 1) })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '刷新实例' }).click()
  await expect(page.getByRole('button', { name: '刷新实例' })).toBeDisabled()
  await expect(page.getByRole('button', { name: '关机' })).toBeDisabled()
  releaseJob()
  await expect(page.getByText('实例状态已刷新')).toBeVisible()
  expect(refreshCalls).toBe(1)
})

test('settings save disables submit while the config request is in flight', async ({ page }) => {
  let saveCalls = 0
  let releaseSave!: (value?: unknown) => void
  const saveReady = new Promise((resolve) => { releaseSave = resolve })
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/config', async (route) => {
    if (route.request().method() === 'PUT') {
      saveCalls += 1
      await saveReady
      return route.fulfill({ json: { success: true } })
    }
    return route.fulfill({ json: dashboardConfig })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.getByRole('button', { name: '保存更改' })).toBeDisabled()
  releaseSave()
  await expect(page.getByText('配置已安全保存')).toBeVisible()
  expect(saveCalls).toBe(1)
})

test('login disables submit while the auth request is in flight', async ({ page }) => {
  let loginCalls = 0
  let authed = false
  let releaseLogin!: (value?: unknown) => void
  const loginReady = new Promise((resolve) => { releaseLogin = resolve })
  await mockInitStatus(page, true)
  await page.route('**/api/v1/auth/login', async (route) => {
    loginCalls += 1
    await loginReady
    authed = true
    return route.fulfill({ json: { success: true, csrf_token: 'test-csrf' } })
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
  await page.getByLabel('管理员密码').fill(TEST_PASSWORD)
  await page.getByRole('button', { name: '安全登录' }).click()
  await expect(page.getByRole('button', { name: '安全登录' })).toBeDisabled()
  releaseLogin()
  await expect(page.getByRole('heading', { name: '资源控制台' })).toBeVisible({ timeout: 30_000 })
  expect(loginCalls).toBe(1)
})

test('wizard disables finish while setup is in flight', async ({ page }) => {
  let setupCalls = 0
  let releaseSetup!: (value?: unknown) => void
  const setupReady = new Promise((resolve) => { releaseSetup = resolve })
  await mockInitStatus(page, false)
  await mockDashboardReads(page)
  await page.route('**/api/v1/setup', async (route) => {
    setupCalls += 1
    expect(route.request().method()).toBe('POST')
    await setupReady
    return route.fulfill({ status: 201, json: { success: true, csrf_token: 'test-csrf' } })
  })

  await page.goto('/')
  const passwords = page.locator('input[type="password"]')
  await passwords.nth(0).fill(TEST_PASSWORD)
  await passwords.nth(1).fill(TEST_PASSWORD)
  await page.getByRole('button', { name: '继续' }).click()
  await page.getByRole('button', { name: '继续' }).click()
  await page.getByRole('button', { name: '完成安装' }).click()
  await expect(page.getByRole('button', { name: '完成安装' })).toBeDisabled()
  releaseSetup()
  await expect(page.getByRole('heading', { name: '资源控制台' })).toBeVisible({ timeout: 30_000 })
  expect(setupCalls).toBe(1)
})

test('settings notify test disables submit while the job is in flight', async ({ page }) => {
  let testCalls = 0
  let releaseJob!: (value?: unknown) => void
  const jobReady = new Promise((resolve) => { releaseJob = resolve })
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/notifications/test/email', (route) => {
    testCalls += 1
    expect(route.request().method()).toBe('POST')
    const job = jobFixture('notify-email-busy', 'queued')
    job.type = 'test_notification'
    return route.fulfill({ status: 202, json: job })
  })
  await page.route('**/api/v1/jobs/**', async (route) => {
    await jobReady
    const job = jobFixture('notify-email-busy', 'completed')
    job.type = 'test_notification'
    return route.fulfill({ json: job })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: '发送测试' }).click()
  await expect(page.getByRole('button', { name: '发送测试' })).toBeDisabled()
  releaseJob()
  await expect(page.getByText('测试通知已送达')).toBeVisible()
  expect(testCalls).toBe(1)
})

test('about update check disables submit while the info request is in flight', async ({ page }) => {
  let checkCalls = 0
  let releaseCheck!: (value?: unknown) => void
  const checkReady = new Promise((resolve) => { releaseCheck = resolve })
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/system/info**', async (route) => {
    const check = new URL(route.request().url()).searchParams.get('check') === '1'
    const payload = {
      version: 'v2.0.1',
      commit: 'abc1234',
      built_at: 'github-run-12345',
      repository: 'https://github.com/wang4386/CDT-Monitor',
      release_url: 'https://github.com/wang4386/CDT-Monitor/releases',
      ...(check ? { latest_version: 'v2.0.2' } : {}),
    }
    if (check) {
      checkCalls += 1
      await checkReady
    }
    return route.fulfill({ json: payload })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '关于' }).click()
  await page.getByRole('button', { name: '检查更新' }).click()
  await expect(page.getByRole('button', { name: '检查更新' })).toBeDisabled()
  releaseCheck()
  await expect(page.getByText('版本检查完成')).toBeVisible()
  expect(checkCalls).toBe(1)
})

test('admin password update disables submit while the request is in flight', async ({ page }) => {
  let updateCalls = 0
  let releaseUpdate!: (value?: unknown) => void
  const updateReady = new Promise((resolve) => { releaseUpdate = resolve })
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/admin/passkeys', (route) => route.fulfill({ json: { passkeys: [] } }))
  await page.route('**/api/v1/admin/password', async (route) => {
    updateCalls += 1
    expect(route.request().method()).toBe('PUT')
    await updateReady
    return route.fulfill({ json: { success: true } })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '管理员' }).click()
  await page.getByLabel('当前密码').fill(TEST_PASSWORD)
  await page.getByLabel('新密码', { exact: true }).fill('Rotated-Password-42!')
  await page.getByLabel('确认新密码').fill('Rotated-Password-42!')
  await page.getByRole('button', { name: '保存新密码' }).click()
  await expect(page.getByRole('button', { name: '保存新密码' })).toBeDisabled()
  releaseUpdate()
  await expect(page.getByText('管理员密码已更新')).toBeVisible()
  expect(updateCalls).toBe(1)
})

test('admin passkey create stays disabled without HTTPS', async ({ page }) => {
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/admin/passkeys', (route) => route.fulfill({ json: { passkeys: [] } }))

  await page.goto('/')
  await page.getByRole('button', { name: '管理员' }).click()
  await expect(page.getByRole('button', { name: '创建 Passkey' })).toBeDisabled()
  await expect(page.getByText('Passkey 只能在 HTTPS 安全上下文中创建')).toBeVisible()
})

test('admin passkeys treat a null passkeys array as empty', async ({ page }) => {
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/admin/passkeys', (route) => route.fulfill({ json: { passkeys: null } }))

  await page.goto('/')
  await page.getByRole('button', { name: '管理员' }).click()
  await expect(page.getByText('尚未创建管理员 Passkey')).toBeVisible()
})

test('settings API keys show loading while the list request is in flight', async ({ page }) => {
  let releaseList!: (value?: unknown) => void
  const listReady = new Promise((resolve) => { releaseList = resolve })
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/api-keys', async (route) => {
    await listReady
    return route.fulfill({ json: { keys: [] } })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: 'API Key' }).click()
  await expect(page.getByText('加载 API Key')).toBeVisible()
  releaseList()
  await expect(page.getByRole('button', { name: '创建 Key' })).toBeVisible()
  await expect(page.locator('.key-row')).toHaveCount(0)
})

test('settings API key create stays disabled without a name', async ({ page }) => {
  let createCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/api-keys', (route) => {
    if (route.request().method() === 'POST') {
      createCalls += 1
      return route.fulfill({ status: 201, json: { key: { id: 1, name: 'x', scopes: ['widget:read'], created_at: new Date().toISOString() }, token: 'cdt_token' } })
    }
    return route.fulfill({ json: { keys: [] } })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: 'API Key' }).click()
  await page.getByLabel('名称').fill('')
  await expect(page.getByRole('button', { name: '创建 Key' })).toBeDisabled()
  expect(createCalls).toBe(0)
})

test('settings API key create stays disabled without a scope', async ({ page }) => {
  let createCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/api-keys', (route) => {
    if (route.request().method() === 'POST') {
      createCalls += 1
      return route.fulfill({ status: 201, json: { key: { id: 1, name: '桌面小组件', scopes: ['widget:read'], created_at: new Date().toISOString() }, token: 'cdt_token' } })
    }
    return route.fulfill({ json: { keys: [] } })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: 'API Key' }).click()
  await page.getByText('读取状态', { exact: true }).click()
  await expect(page.getByRole('button', { name: '创建 Key' })).toBeDisabled()
  expect(createCalls).toBe(0)
})

test('settings API key copy posts the live token to the clipboard', async ({ page }) => {
  const token = 'cdt_copy_token_once'
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.context().grantPermissions(['clipboard-read', 'clipboard-write'])
  await page.route('**/api/v1/api-keys', async (route) => {
    if (route.request().method() === 'POST') {
      return route.fulfill({ status: 201, json: {
        key: { id: 11, name: '桌面小组件', scopes: ['widget:read'], created_at: new Date().toISOString() },
        token,
      } })
    }
    return route.fulfill({ json: { keys: [] } })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: 'API Key' }).click()
  await page.getByRole('button', { name: '创建 Key' }).click()
  await expect(page.getByText('仅显示一次')).toBeVisible()
  await page.getByRole('button', { name: '复制' }).click()
  await expect(page.getByText('已复制到剪贴板')).toBeVisible()
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(token)
})

test('settings API keys retry reloads the live key list', async ({ page }) => {
  let listCalls = 0
  let allowSuccess = false
  const existing = { id: 12, name: '桌面小组件', scopes: ['widget:read'], created_at: new Date().toISOString() }
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/api-keys', (route) => {
    listCalls += 1
    if (!allowSuccess) {
      return route.fulfill({
        status: 500,
        json: { error: { code: 'api_keys_failed', message: 'API Key 加载失败' } },
      })
    }
    return route.fulfill({ json: { keys: [existing] } })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: 'API Key' }).click()
  await expect(page.locator('.inline-error')).toContainText('API Key 加载失败')
  allowSuccess = true
  await page.getByRole('button', { name: '重试' }).click()
  await expect(page.locator('.key-row')).toContainText('桌面小组件')
  expect(listCalls).toBeGreaterThanOrEqual(2)
})

test('login stays disabled without a password', async ({ page }) => {
  let loginCalls = 0
  await mockInitStatus(page, true)
  await mockUnauthorizedSession(page)
  await page.route('**/api/v1/auth/login', (route) => {
    loginCalls += 1
    return route.fulfill({ json: { success: true, csrf_token: 'test-csrf' } })
  })

  await page.goto('/')
  await expect(page.getByRole('heading', { name: '欢迎回来' })).toBeVisible()
  await expect(page.getByRole('button', { name: '安全登录' })).toBeDisabled()
  expect(loginCalls).toBe(0)
})

test('login hides passkey sign-in without HTTPS', async ({ page }) => {
  await mockInitStatus(page, true)
  await mockUnauthorizedSession(page)

  await page.goto('/')
  await expect(page.getByRole('heading', { name: '欢迎回来' })).toBeVisible()
  await expect(page.getByRole('button', { name: '使用 Passkey 登录' })).toHaveCount(0)
  await expect(page.getByText('Passkey 登录只能在 HTTPS 安全上下文中使用')).toBeVisible()
})

test('login password visibility toggle reveals the password field', async ({ page }) => {
  await mockInitStatus(page, true)
  await mockUnauthorizedSession(page)

  await page.goto('/')
  const password = page.getByLabel('管理员密码')
  await expect(password).toHaveAttribute('type', 'password')
  await page.getByRole('button', { name: '显示密码' }).click()
  await expect(password).toHaveAttribute('type', 'text')
  await page.getByRole('button', { name: '隐藏密码' }).click()
  await expect(password).toHaveAttribute('type', 'password')
})

test('settings logs reload heartbeat after action logs_failed', async ({ page }) => {
  let heartbeatReads = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/logs**', (route) => {
    const tab = new URL(route.request().url()).searchParams.get('tab')
    if (tab === 'heartbeat') {
      heartbeatReads += 1
      return route.fulfill({ json: { logs: [{ id: 3, type: 'heartbeat', message: '心跳采样', created_at: new Date().toISOString() }] } })
    }
    return route.fulfill({
      status: 500,
      json: { error: { code: 'logs_failed', message: '日志操作失败' } },
    })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '日志' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '日志操作失败' }).first()).toBeVisible()
  await page.getByRole('button', { name: '心跳' }).click()
  await expect(page.getByText('心跳采样')).toBeVisible()
  expect(heartbeatReads).toBeGreaterThanOrEqual(1)
})

test('history chart closes from the dialog contract', async ({ page }) => {
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/accounts/1/history', (route) => route.fulfill({ json: emptyHistory }))

  await page.goto('/')
  await page.getByRole('button', { name: '查看历史流量' }).click()
  await expect(page.getByRole('dialog').getByRole('heading', { name: '香港测试节点' })).toBeVisible()
  await page.getByRole('dialog').getByRole('button', { name: '关闭' }).click()
  await expect(page.getByRole('dialog')).toHaveCount(0)
  await expect(page.getByRole('heading', { name: '资源控制台' })).toBeVisible()
})

test('wizard password visibility toggle reveals both password fields', async ({ page }) => {
  await mockInitStatus(page, false)

  await page.goto('/')
  const password = page.getByLabel('管理员密码')
  const confirm = page.getByLabel('确认密码')
  await expect(password).toHaveAttribute('type', 'password')
  await expect(confirm).toHaveAttribute('type', 'password')
  await page.getByRole('button', { name: '显示密码' }).first().click()
  await expect(password).toHaveAttribute('type', 'text')
  await expect(confirm).toHaveAttribute('type', 'text')
  await page.getByRole('button', { name: '隐藏密码' }).first().click()
  await expect(password).toHaveAttribute('type', 'password')
  await expect(confirm).toHaveAttribute('type', 'password')
})

test('wizard back stays disabled on the first setup step', async ({ page }) => {
  await mockInitStatus(page, false)

  await page.goto('/')
  await expect(page.getByRole('heading', { name: '创建安全边界' })).toBeVisible()
  await expect(page.getByRole('button', { name: '返回' })).toBeDisabled()
})

test('wizard back returns from automation policy to the password step', async ({ page }) => {
  await mockInitStatus(page, false)

  await page.goto('/')
  const passwords = page.locator('input[type="password"]')
  await passwords.nth(0).fill(TEST_PASSWORD)
  await passwords.nth(1).fill(TEST_PASSWORD)
  await page.getByRole('button', { name: '继续' }).click()
  await expect(page.getByRole('heading', { name: '设定自动化策略' })).toBeVisible()
  await page.getByRole('button', { name: '返回' }).click()
  await expect(page.getByRole('heading', { name: '创建安全边界' })).toBeVisible()
  await expect(page.getByLabel('管理员密码')).toHaveValue(TEST_PASSWORD)
})

test('wizard password strength follows the live password contract', async ({ page }) => {
  await mockInitStatus(page, false)

  await page.goto('/')
  await expect(page.getByLabel('密码强度 0/4')).toBeVisible()
  await page.getByLabel('管理员密码').fill('short')
  await expect(page.getByLabel('密码强度 0/4')).toBeVisible()
  await page.getByLabel('管理员密码').fill(TEST_PASSWORD)
  await expect(page.getByLabel('密码强度 4/4')).toBeVisible()
})

test('wizard back returns from instance setup to automation policy', async ({ page }) => {
  await mockInitStatus(page, false)

  await page.goto('/')
  const passwords = page.locator('input[type="password"]')
  await passwords.nth(0).fill(TEST_PASSWORD)
  await passwords.nth(1).fill(TEST_PASSWORD)
  await page.getByRole('button', { name: '继续' }).click()
  await page.getByRole('button', { name: '继续' }).click()
  await expect(page.getByRole('heading', { name: '连接云端实例' })).toBeVisible()
  await page.getByRole('button', { name: '返回' }).click()
  await expect(page.getByRole('heading', { name: '设定自动化策略' })).toBeVisible()
})

test('setup drops blank access_key_id accounts from the payload', async ({ page }) => {
  let accounts: unknown
  await mockInitStatus(page, false)
  await page.route('**/api/v1/setup', async (route) => {
    const body = JSON.parse(route.request().postData() || '{}') as Record<string, unknown>
    expectKnownKeys(body, CONFIG_OBJECT_KEYS)
    accounts = body.accounts
    await route.fulfill({ status: 201, json: { success: true, csrf_token: 'test-csrf' } })
  })
  await mockDashboardReads(page)

  await page.goto('/')
  const passwords = page.locator('input[type="password"]')
  await passwords.nth(0).fill(TEST_PASSWORD)
  await passwords.nth(1).fill(TEST_PASSWORD)
  await page.getByRole('button', { name: '继续' }).click()
  await page.getByRole('button', { name: '继续' }).click()
  await page.getByLabel('AccessKey ID').fill('   ')
  await page.getByRole('button', { name: '完成安装' }).click()
  await expect(page.getByRole('heading', { name: '资源控制台' })).toBeVisible({ timeout: 30_000 })
  expect(accounts).toEqual([])
})

test('settings panel closes from the dialog contract', async ({ page }) => {
  await mockInitStatus(page, true)
  await mockDashboardReads(page)

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await expect(page.getByRole('heading', { name: '控制台设置' })).toBeVisible()
  await page.locator('.settings-panel').getByRole('button', { name: '关闭' }).click()
  await expect(page.getByRole('heading', { name: '控制台设置' })).toHaveCount(0)
  await expect(page.getByRole('heading', { name: '资源控制台' })).toBeVisible()
})

test('admin settings close from the dialog contract', async ({ page }) => {
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/admin/passkeys', (route) => route.fulfill({ json: { passkeys: [] } }))

  await page.goto('/')
  await page.getByRole('button', { name: '管理员' }).click()
  await expect(page.getByRole('heading', { name: '管理员设置' })).toBeVisible()
  await page.getByRole('dialog', { name: '管理员设置' }).getByRole('button', { name: '关闭' }).click()
  await expect(page.getByRole('dialog', { name: '管理员设置' })).toHaveCount(0)
  await expect(page.getByRole('heading', { name: '资源控制台' })).toBeVisible()
})

test('history chart switches back to hourly range from daily', async ({ page }) => {
  const hourStart = Math.floor(Date.now() / 3_600_000) * 3_600_000
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/accounts/1/history', (route) => route.fulfill({ json: {
    hourly: [{ at: new Date(hourStart).toISOString(), traffic: 1.25 }],
    daily: [{ at: new Date(hourStart).toISOString(), traffic: 9.5 }],
  } }))

  await page.goto('/')
  await page.getByRole('button', { name: '查看历史流量' }).click()
  await expect(page.locator('.chart-area .recharts-line-dot').last()).toBeVisible()
  await page.getByRole('button', { name: '30 天' }).click()
  await expect(page.locator('.recharts-bar-rectangle .recharts-rectangle').first()).toBeVisible()
  await page.getByRole('button', { name: '24 小时' }).click()
  await expect(page.locator('.chart-area .recharts-line-dot').last()).toBeVisible()
})

test('settings webhook template cancel does not save', async ({ page }) => {
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
  await expect(page.getByRole('dialog', { name: 'Bark 模板配置' })).toBeVisible()
  await page.getByRole('button', { name: '取消' }).click()
  await expect(page.getByRole('dialog', { name: 'Bark 模板配置' })).toHaveCount(0)
  expect(saveCalls).toBe(0)
})

test('settings webhook template close does not save', async ({ page }) => {
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
  const dialog = page.getByRole('dialog', { name: 'Bark 模板配置' })
  await expect(dialog).toBeVisible()
  await dialog.getByRole('button', { name: '关闭' }).click()
  await expect(dialog).toHaveCount(0)
  expect(saveCalls).toBe(0)
})

test('settings webhook variable picker posts the live body contract', async ({ page }) => {
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
  await page.getByTitle('插入 #MSG#').click()
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.getByText('配置已安全保存')).toBeVisible()
  expect(savedWebhook).toMatchObject({ body: '#MSG#' })
})

test('wizard step labels follow the setup contract', async ({ page }) => {
  await mockInitStatus(page, false)

  await page.goto('/')
  await expect(page.getByText('STEP 1 OF 3')).toBeVisible()
  const passwords = page.locator('input[type="password"]')
  await passwords.nth(0).fill(TEST_PASSWORD)
  await passwords.nth(1).fill(TEST_PASSWORD)
  await page.getByRole('button', { name: '继续' }).click()
  await expect(page.getByText('STEP 2 OF 3')).toBeVisible()
  await page.getByRole('button', { name: '继续' }).click()
  await expect(page.getByText('STEP 3 OF 3')).toBeVisible()
})

test('dashboard mobile menu opens settings', async ({ page }) => {
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.setViewportSize({ width: 390, height: 844 })

  await page.goto('/')
  await page.getByRole('button', { name: '菜单' }).click()
  await expect(page.getByRole('button', { name: '菜单' })).toHaveAttribute('aria-expanded', 'true')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await expect(page.getByRole('heading', { name: '控制台设置' })).toBeVisible()
})

test('settings webhook template scrim close does not save', async ({ page }) => {
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
  await expect(page.getByRole('dialog', { name: 'Bark 模板配置' })).toBeVisible()
  await page.locator('.modal-layer--nested .modal-scrim').click({ position: { x: 8, y: 8 } })
  await expect(page.getByRole('dialog', { name: 'Bark 模板配置' })).toHaveCount(0)
  await expect(page.getByRole('heading', { name: '控制台设置' })).toBeVisible()
  expect(saveCalls).toBe(0)
})

test('settings panel scrim close returns to the dashboard', async ({ page }) => {
  await mockInitStatus(page, true)
  await mockDashboardReads(page)

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await expect(page.getByRole('heading', { name: '控制台设置' })).toBeVisible()
  await page.locator('.modal-layer .modal-scrim').click({ position: { x: 8, y: 8 } })
  await expect(page.getByRole('heading', { name: '控制台设置' })).toHaveCount(0)
  await expect(page.getByRole('heading', { name: '资源控制台' })).toBeVisible()
})

test('history chart scrim close returns to the dashboard', async ({ page }) => {
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/accounts/1/history', (route) => route.fulfill({ json: emptyHistory }))

  await page.goto('/')
  await page.getByRole('button', { name: '查看历史流量' }).click()
  await expect(page.getByRole('dialog').getByRole('heading', { name: '香港测试节点' })).toBeVisible()
  await page.locator('.modal-layer .modal-scrim').click({ position: { x: 8, y: 8 } })
  await expect(page.getByRole('dialog')).toHaveCount(0)
  await expect(page.getByRole('heading', { name: '资源控制台' })).toBeVisible()
})

test('admin settings scrim close returns to the dashboard', async ({ page }) => {
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/admin/passkeys', (route) => route.fulfill({ json: { passkeys: [] } }))

  await page.goto('/')
  await page.getByRole('button', { name: '管理员' }).click()
  await expect(page.getByRole('dialog', { name: '管理员设置' })).toBeVisible()
  await page.locator('.modal-layer .modal-scrim').click({ position: { x: 8, y: 8 } })
  await expect(page.getByRole('dialog', { name: '管理员设置' })).toHaveCount(0)
  await expect(page.getByRole('heading', { name: '资源控制台' })).toBeVisible()
})

test('dashboard mobile menu toggles closed', async ({ page }) => {
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.setViewportSize({ width: 390, height: 844 })

  await page.goto('/')
  await page.getByRole('button', { name: '菜单' }).click()
  await expect(page.getByRole('button', { name: '菜单' })).toHaveAttribute('aria-expanded', 'true')
  await page.getByRole('button', { name: '菜单' }).click()
  await expect(page.getByRole('button', { name: '菜单' })).toHaveAttribute('aria-expanded', 'false')
})

test('logout sends the CSRF header from the cdt_csrf cookie', async ({ page }) => {
  const csrf = 'test-csrf'
  let logoutCsrf = ''
  let logoutCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/auth/logout', (route) => {
    logoutCalls += 1
    expect(route.request().method()).toBe('POST')
    logoutCsrf = route.request().headers()[CSRF_HEADER.toLowerCase()] || ''
    return route.fulfill({ json: { success: true } })
  })

  await page.goto('/')
  await page.context().addCookies([{ name: CSRF_COOKIE, value: csrf, url: page.url() }])
  await page.getByRole('button', { name: '退出' }).click()
  await expect(page.getByRole('heading', { name: '欢迎回来' })).toBeVisible()
  expect(logoutCalls).toBe(1)
  expect(logoutCsrf).toBe(csrf)
})

test('logout returns to login when CSRF check fails', async ({ page }) => {
  let logoutCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/auth/logout', (route) => {
    logoutCalls += 1
    expect(route.request().method()).toBe('POST')
    return route.fulfill({
      status: 403,
      json: { error: { code: 'csrf_failed', message: 'CSRF 校验失败' } },
    })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '退出' }).click()
  await expect(page.getByRole('heading', { name: '欢迎回来' })).toBeVisible()
  expect(logoutCalls).toBe(1)
})

test('dashboard mobile menu logout posts the live auth contract', async ({ page }) => {
  let logoutCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/auth/logout', (route) => {
    logoutCalls += 1
    expect(route.request().method()).toBe('POST')
    return route.fulfill({ json: { success: true } })
  })
  await page.setViewportSize({ width: 390, height: 844 })

  await page.goto('/')
  await page.getByRole('button', { name: '菜单' }).click()
  await page.getByRole('button', { name: '退出' }).click()
  await expect(page.getByRole('heading', { name: '欢迎回来' })).toBeVisible()
  expect(logoutCalls).toBe(1)
})

test('settings webhook test surfaces the job_failed envelope', async ({ page }) => {
  let testCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/notifications/test/webhook', (route) => {
    testCalls += 1
    expect(route.request().method()).toBe('POST')
    const job = jobFixture('notify-webhook-job', 'queued')
    job.type = 'test_notification'
    return route.fulfill({ status: 202, json: job })
  })
  await page.route('**/api/v1/jobs/**', (route) => route.fulfill({
    status: 500,
    json: { error: { code: 'job_failed', message: '任务查询失败' } },
  }))

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: 'Webhook' }).click()
  await page.getByRole('button', { name: '发送测试' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '任务查询失败' }).first()).toBeVisible()
  expect(testCalls).toBe(1)
})

test('settings email test surfaces the job_failed envelope', async ({ page }) => {
  let testCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/notifications/test/email', (route) => {
    testCalls += 1
    expect(route.request().method()).toBe('POST')
    const job = jobFixture('notify-email-job', 'queued')
    job.type = 'test_notification'
    return route.fulfill({ status: 202, json: job })
  })
  await page.route('**/api/v1/jobs/**', (route) => route.fulfill({
    status: 500,
    json: { error: { code: 'job_failed', message: '任务查询失败' } },
  }))

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: '发送测试' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '任务查询失败' }).first()).toBeVisible()
  expect(testCalls).toBe(1)
})

test('settings telegram test surfaces the job_failed envelope', async ({ page }) => {
  let testCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/notifications/test/telegram', (route) => {
    testCalls += 1
    expect(route.request().method()).toBe('POST')
    const job = jobFixture('notify-telegram-job', 'queued')
    job.type = 'test_notification'
    return route.fulfill({ status: 202, json: job })
  })
  await page.route('**/api/v1/jobs/**', (route) => route.fulfill({
    status: 500,
    json: { error: { code: 'job_failed', message: '任务查询失败' } },
  }))

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: 'Telegram' }).click()
  await page.getByRole('button', { name: '发送测试' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '任务查询失败' }).first()).toBeVisible()
  expect(testCalls).toBe(1)
})

test('instance start disables power controls while the job is in flight', async ({ page }) => {
  let startCalls = 0
  let releaseJob!: (value?: unknown) => void
  const jobReady = new Promise((resolve) => { releaseJob = resolve })
  await mockInitStatus(page, true)
  await mockDashboardReads(page, {
    ...dashboardStatus,
    accounts: [{ ...dashboardAccount, instance_status: 'Stopped' }],
  })
  await page.route('**/api/v1/accounts/1/actions/start', (route) => {
    startCalls += 1
    expect(route.request().method()).toBe('POST')
    return route.fulfill({ status: 202, json: jobFixture('start-busy', 'queued', 1) })
  })
  await page.route('**/api/v1/jobs/**', async (route) => {
    await jobReady
    return route.fulfill({ json: jobFixture('start-busy', 'completed', 1) })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '开机' }).click()
  await expect(page.getByRole('button', { name: '开机' })).toBeDisabled()
  await expect(page.getByRole('button', { name: '刷新实例' })).toBeDisabled()
  releaseJob()
  await expect(page.getByText('已发送开机指令')).toBeVisible()
  expect(startCalls).toBe(1)
})

test('instance stop disables power controls while the job is in flight', async ({ page }) => {
  let stopCalls = 0
  let releaseJob!: (value?: unknown) => void
  const jobReady = new Promise((resolve) => { releaseJob = resolve })
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/accounts/1/actions/stop', (route) => {
    stopCalls += 1
    expect(route.request().method()).toBe('POST')
    return route.fulfill({ status: 202, json: jobFixture('stop-busy', 'queued', 1) })
  })
  await page.route('**/api/v1/jobs/**', async (route) => {
    await jobReady
    return route.fulfill({ json: jobFixture('stop-busy', 'completed', 1) })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '关机' }).click()
  await expect(page.getByRole('button', { name: '关机' })).toBeDisabled()
  await expect(page.getByRole('button', { name: '刷新实例' })).toBeDisabled()
  releaseJob()
  await expect(page.getByText('已发送关机指令')).toBeVisible()
  expect(stopCalls).toBe(1)
})

test('instance start surfaces the enqueue_failed envelope', async ({ page }) => {
  let startCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page, {
    ...dashboardStatus,
    accounts: [{ ...dashboardAccount, instance_status: 'Stopped' }],
  })
  await page.route('**/api/v1/accounts/1/actions/start', (route) => {
    startCalls += 1
    expect(route.request().method()).toBe('POST')
    return route.fulfill({
      status: 500,
      json: { error: { code: 'enqueue_failed', message: '任务提交失败' } },
    })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '开机' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '任务提交失败' }).first()).toBeVisible()
  expect(startCalls).toBe(1)
})

test('instance stop surfaces the enqueue_failed envelope', async ({ page }) => {
  let stopCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/accounts/1/actions/stop', (route) => {
    stopCalls += 1
    expect(route.request().method()).toBe('POST')
    return route.fulfill({
      status: 500,
      json: { error: { code: 'enqueue_failed', message: '任务提交失败' } },
    })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '关机' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '任务提交失败' }).first()).toBeVisible()
  expect(stopCalls).toBe(1)
})

test('failed notify job toast omits transport secrets', async ({ page }) => {
  const leaked = 'FIXTURE-SECRET-TOKEN'
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/notifications/test/telegram', (route) => {
    expect(route.request().method()).toBe('POST')
    const job = jobFixture('notify-secret-fail', 'queued')
    job.type = 'test_notification'
    return route.fulfill({ status: 202, json: job })
  })
  await page.route('**/api/v1/jobs/**', (route) => {
    const failed = jobFixture('notify-secret-fail', 'failed')
    failed.type = 'test_notification'
    failed.error = `telegram HTTP 401: https://api.telegram.org/bot${leaked}/sendMessage`
    return route.fulfill({ json: failed })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: 'Telegram' }).click()
  await page.getByRole('button', { name: '发送测试' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: JOB_FAILED_USER_MESSAGE }).first()).toBeVisible()
  await expect(page.locator('.toast-stack')).not.toContainText(leaked)
})

test('telegram notify timeout surfaces the in-progress job message', async ({ page }) => {
  await page.clock.install()
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/notifications/test/telegram', (route) => {
    expect(route.request().method()).toBe('POST')
    const job = jobFixture('notify-telegram-timeout', 'queued')
    job.type = 'test_notification'
    return route.fulfill({ status: 202, json: job })
  })
  await page.route('**/api/v1/jobs/**', (route) => {
    const queued = jobFixture('notify-telegram-timeout', 'queued')
    queued.type = 'test_notification'
    queued.error = 'FIXTURE-SECRET-TOKEN'
    return route.fulfill({ json: queued })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: 'Telegram' }).click()
  const jobPolled = page.waitForRequest('**/api/v1/jobs/**')
  await page.getByRole('button', { name: '发送测试' }).click()
  await jobPolled
  await page.clock.fastForward(71_000)
  await expect(page.locator('.toast--error').filter({ hasText: '任务仍在后台执行，请稍后刷新' }).first()).toBeVisible()
  await expect(page.locator('.toast-stack')).not.toContainText('FIXTURE-SECRET-TOKEN')
})

test('settings API key create posts optional expires_at', async ({ page }) => {
  const expiresLocal = '2026-12-31T23:59'
  const created = {
    id: 13,
    name: '桌面小组件',
    scopes: ['widget:read'],
    created_at: new Date().toISOString(),
    expires_at: new Date(expiresLocal).toISOString(),
  }
  let createCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/api-keys', async (route) => {
    if (route.request().method() === 'POST') {
      createCalls += 1
      const body = JSON.parse(route.request().postData() || '{}') as { name?: string; scopes?: string[]; expires_at?: string }
      expect(body.name).toBe('桌面小组件')
      expect(body.scopes).toEqual(['widget:read'])
      expect(new Date(body.expires_at || '').toISOString()).toBe(new Date(expiresLocal).toISOString())
      return route.fulfill({ status: 201, json: { key: created, token: 'cdt_expiring_token' } })
    }
    return route.fulfill({ json: { keys: createCalls > 0 ? [created] : [] } })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: 'API Key' }).click()
  await page.getByLabel('过期时间（可选）').fill(expiresLocal)
  await page.getByRole('button', { name: '创建 Key' }).click()
  await expect(page.getByText('仅显示一次')).toBeVisible()
  await expect(page.locator('.key-row')).toContainText('过期')
  expect(createCalls).toBe(1)
})

test('failed stop job surfaces a generic failure toast', async ({ page }) => {
  const leaked = 'FIXTURE-SECRET-TOKEN'
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/accounts/1/actions/stop', (route) => {
    expect(route.request().method()).toBe('POST')
    return route.fulfill({ status: 202, json: jobFixture('stop-fail', 'queued', 1) })
  })
  await page.route('**/api/v1/jobs/**', (route) => {
    const failed = jobFixture('stop-fail', 'failed', 1)
    failed.error = `aliyun HTTP 403: AccessKeyId=${leaked}`
    return route.fulfill({ json: failed })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '关机' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: JOB_FAILED_USER_MESSAGE }).first()).toBeVisible()
  await expect(page.locator('.toast-stack')).not.toContainText(leaked)
})

test('instance stop timeout surfaces the in-progress job message', async ({ page }) => {
  await page.clock.install()
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/accounts/1/actions/stop', (route) => {
    expect(route.request().method()).toBe('POST')
    return route.fulfill({ status: 202, json: jobFixture('stop-timeout', 'queued', 1) })
  })
  await page.route('**/api/v1/jobs/**', (route) => {
    const queued = jobFixture('stop-timeout', 'queued', 1)
    queued.error = 'FIXTURE-SECRET-TOKEN'
    return route.fulfill({ json: queued })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '关机' }).click()
  await page.clock.fastForward(71_000)
  await expect(page.locator('.toast--error').filter({ hasText: '任务仍在后台执行，请稍后刷新' }).first()).toBeVisible()
  await expect(page.locator('.toast-stack')).not.toContainText('FIXTURE-SECRET-TOKEN')
})

test('instance start surfaces the job_failed envelope', async ({ page }) => {
  let startCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page, {
    ...dashboardStatus,
    accounts: [{ ...dashboardAccount, instance_status: 'Stopped' }],
  })
  await page.route('**/api/v1/accounts/1/actions/start', (route) => {
    startCalls += 1
    expect(route.request().method()).toBe('POST')
    return route.fulfill({ status: 202, json: jobFixture('start-poll', 'queued', 1) })
  })
  await page.route('**/api/v1/jobs/**', (route) => route.fulfill({
    status: 500,
    json: { error: { code: 'job_failed', message: '任务查询失败' } },
  }))

  await page.goto('/')
  await page.getByRole('button', { name: '开机' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '任务查询失败' }).first()).toBeVisible()
  expect(startCalls).toBe(1)
})

test('instance stop surfaces the job_failed envelope', async ({ page }) => {
  let stopCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/accounts/1/actions/stop', (route) => {
    stopCalls += 1
    expect(route.request().method()).toBe('POST')
    return route.fulfill({ status: 202, json: jobFixture('stop-poll', 'queued', 1) })
  })
  await page.route('**/api/v1/jobs/**', (route) => route.fulfill({
    status: 500,
    json: { error: { code: 'job_failed', message: '任务查询失败' } },
  }))

  await page.goto('/')
  await page.getByRole('button', { name: '关机' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '任务查询失败' }).first()).toBeVisible()
  expect(stopCalls).toBe(1)
})

test('settings webhook GET matches the live scrubbed read model', async ({ page }) => {
  const configured = {
    ...dashboardConfig,
    notifications: {
      ...dashboardConfig.notifications,
      webhook: liveGetWebhook({
        enabled: true,
        method: 'POST',
        request_type: 'JSON',
        provider: 'dingtalk',
        secret_configured: true,
        headers_configured: true,
        url_configured: true,
        body_configured: true,
      }),
    },
  }
  let savedWebhook: Record<string, unknown> | undefined
  await mockInitStatus(page, true)
  await mockDashboardReads(page, dashboardStatus, configured)
  await page.route('**/api/v1/config', async (route) => {
    if (route.request().method() === 'PUT') {
      const payload = JSON.parse(route.request().postData() || '{}') as { notifications?: { webhook?: Record<string, unknown> } }
      expectKnownKeys(payload, CONFIG_OBJECT_KEYS)
      savedWebhook = payload.notifications?.webhook
      return route.fulfill({ json: { success: true } })
    }
    return route.fulfill({ json: configured })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: 'Webhook' }).click()
  await expect(page.getByLabel('Webhook URL · 已配置')).toHaveValue('')
  await expect(page.getByLabel('自定义 Headers · 已配置')).toHaveValue('')
  await expect(page.getByLabel('Body 模板 · 已配置')).toHaveValue('')
  await expect(page.getByLabel('钉钉加签密钥 · 已配置')).toHaveValue('')
  await expect(page.getByText('__clear__')).toHaveCount(0)
  await expect(page.getByText('access_token')).toHaveCount(0)
  await expect(page.getByText('ding-token')).toHaveCount(0)
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.getByText('配置已安全保存')).toBeVisible()
  expect(savedWebhook).toMatchObject({
    enabled: true,
    provider: 'dingtalk',
    method: 'POST',
    request_type: 'JSON',
    secret_configured: true,
    headers_configured: true,
    url_configured: true,
    body_configured: true,
  })
  expect(savedWebhook).not.toHaveProperty('url')
  expect(savedWebhook).not.toHaveProperty('headers')
  expect(savedWebhook).not.toHaveProperty('body')
  expect(savedWebhook).not.toHaveProperty('secret')
  expect(JSON.stringify(savedWebhook)).not.toContain('__clear__')
})

test('settings dingtalk webhook template clears configured headers from a scrubbed GET', async ({ page }) => {
  const configured = {
    ...dashboardConfig,
    notifications: {
      ...dashboardConfig.notifications,
      webhook: liveGetWebhook({
        enabled: true,
        method: 'POST',
        request_type: 'JSON',
        headers_configured: true,
        url_configured: true,
        body_configured: true,
      }),
    },
  }
  let savedWebhook: Record<string, unknown> | undefined
  await mockInitStatus(page, true)
  await mockDashboardReads(page, dashboardStatus, configured)
  await page.route('**/api/v1/config', async (route) => {
    if (route.request().method() === 'PUT') {
      const payload = JSON.parse(route.request().postData() || '{}') as { notifications?: { webhook?: Record<string, unknown> } }
      expectKnownKeys(payload, CONFIG_OBJECT_KEYS)
      savedWebhook = payload.notifications?.webhook
      return route.fulfill({ json: { success: true } })
    }
    return route.fulfill({ json: configured })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: 'Webhook' }).click()
  await expect(page.getByLabel('自定义 Headers · 已配置')).toHaveValue('')
  await page.locator('#webhook-template').click()
  await page.getByRole('option', { name: '钉钉群机器人' }).click()
  await page.getByLabel('机器人 Access Token').fill('ding-token')
  await page.getByRole('button', { name: '生成 Webhook' }).click()
  await expect(page.getByText('钉钉群机器人 模板已生成，请检查后保存')).toBeVisible()
  await expect(page.getByText('__clear__')).toHaveCount(0)
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.getByText('配置已安全保存')).toBeVisible()
  expect(savedWebhook).toMatchObject({
    enabled: true,
    provider: 'dingtalk',
    method: 'POST',
    request_type: 'JSON',
    headers: '__clear__',
    url: 'https://oapi.dingtalk.com/robot/send?access_token=ding-token',
    body: '{\n  "msgtype": "text",\n  "text": {\n    "content": "#MSG#"\n  }\n}',
  })
  expect(savedWebhook?.headers).not.toBe('')
})

test('settings wecom webhook template clears configured headers from a scrubbed GET', async ({ page }) => {
  const configured = {
    ...dashboardConfig,
    notifications: {
      ...dashboardConfig.notifications,
      webhook: liveGetWebhook({
        enabled: true,
        method: 'POST',
        request_type: 'JSON',
        headers_configured: true,
        url_configured: true,
        body_configured: true,
      }),
    },
  }
  let savedWebhook: Record<string, unknown> | undefined
  await mockInitStatus(page, true)
  await mockDashboardReads(page, dashboardStatus, configured)
  await page.route('**/api/v1/config', async (route) => {
    if (route.request().method() === 'PUT') {
      const payload = JSON.parse(route.request().postData() || '{}') as { notifications?: { webhook?: Record<string, unknown> } }
      expectKnownKeys(payload, CONFIG_OBJECT_KEYS)
      savedWebhook = payload.notifications?.webhook
      return route.fulfill({ json: { success: true } })
    }
    return route.fulfill({ json: configured })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: 'Webhook' }).click()
  await expect(page.getByLabel('自定义 Headers · 已配置')).toHaveValue('')
  await expect(page.getByLabel('Webhook URL · 已配置')).toHaveValue('')
  await page.locator('#webhook-template').click()
  await page.getByRole('option', { name: '微信群机器人' }).click()
  await page.getByLabel('微信群机器人 Key').fill('wecom-key')
  await page.getByRole('button', { name: '生成 Webhook' }).click()
  await expect(page.getByText('微信群机器人 模板已生成，请检查后保存')).toBeVisible()
  await expect(page.getByText('__clear__')).toHaveCount(0)
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.getByText('配置已安全保存')).toBeVisible()
  expect(savedWebhook).toMatchObject({
    enabled: true,
    provider: 'wecom',
    method: 'POST',
    request_type: 'JSON',
    headers: '__clear__',
    url: 'https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=wecom-key',
    body: '{\n  "msgtype": "text",\n  "text": {\n    "content": "#MSG#"\n  }\n}',
  })
  expect(savedWebhook?.headers).not.toBe('')
})

test('settings wxpusher webhook template clears configured headers from a scrubbed GET', async ({ page }) => {
  const configured = {
    ...dashboardConfig,
    notifications: {
      ...dashboardConfig.notifications,
      webhook: liveGetWebhook({
        enabled: true,
        method: 'POST',
        request_type: 'JSON',
        headers_configured: true,
        url_configured: true,
        body_configured: true,
      }),
    },
  }
  let savedWebhook: Record<string, unknown> | undefined
  await mockInitStatus(page, true)
  await mockDashboardReads(page, dashboardStatus, configured)
  await page.route('**/api/v1/config', async (route) => {
    if (route.request().method() === 'PUT') {
      const payload = JSON.parse(route.request().postData() || '{}') as { notifications?: { webhook?: Record<string, unknown> } }
      expectKnownKeys(payload, CONFIG_OBJECT_KEYS)
      savedWebhook = payload.notifications?.webhook
      return route.fulfill({ json: { success: true } })
    }
    return route.fulfill({ json: configured })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: 'Webhook' }).click()
  await expect(page.getByLabel('自定义 Headers · 已配置')).toHaveValue('')
  await expect(page.getByLabel('Body 模板 · 已配置')).toHaveValue('')
  await page.locator('#webhook-template').click()
  await page.getByRole('option', { name: 'WxPusher' }).click()
  await page.getByLabel('AppToken').fill('AT_test')
  await page.getByLabel('UID').fill('UID_test')
  await page.getByRole('button', { name: '生成 Webhook' }).click()
  await expect(page.getByText('WxPusher 模板已生成，请检查后保存')).toBeVisible()
  await expect(page.getByText('__clear__')).toHaveCount(0)
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.getByText('配置已安全保存')).toBeVisible()
  expect(savedWebhook).toMatchObject({
    enabled: true,
    provider: 'wxpusher',
    method: 'POST',
    request_type: 'JSON',
    headers: '__clear__',
    url: 'https://wxpusher.zjiecode.com/api/send/message',
    body: '{\n  "appToken": "AT_test",\n  "content": "#MSG#",\n  "summary": "#TITLE#",\n  "contentType": 1,\n  "uids": [\n    "UID_test"\n  ]\n}',
  })
  expect(savedWebhook?.headers).not.toBe('')
})

test('instance start surfaces the invalid_action envelope', async ({ page }) => {
  let startCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page, {
    ...dashboardStatus,
    accounts: [{ ...dashboardAccount, instance_status: 'Stopped' }],
  })
  await page.route('**/api/v1/accounts/1/actions/start', (route) => {
    startCalls += 1
    expect(route.request().method()).toBe('POST')
    return route.fulfill({
      status: 400,
      json: { error: { code: 'invalid_action', message: 'action must be start or stop' } },
    })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '开机' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: 'action must be start or stop' }).first()).toBeVisible()
  expect(startCalls).toBe(1)
})

test('instance stop surfaces the invalid_action envelope', async ({ page }) => {
  let stopCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/accounts/1/actions/stop', (route) => {
    stopCalls += 1
    expect(route.request().method()).toBe('POST')
    return route.fulfill({
      status: 400,
      json: { error: { code: 'invalid_action', message: 'action must be start or stop' } },
    })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '关机' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: 'action must be start or stop' }).first()).toBeVisible()
  expect(stopCalls).toBe(1)
})

test('settings API key create surfaces the invalid_scope envelope', async ({ page }) => {
  let createCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/api-keys', (route) => {
    if (route.request().method() === 'POST') {
      createCalls += 1
      expect(JSON.parse(route.request().postData() || '{}')).toMatchObject({
        name: '桌面小组件',
        scopes: ['widget:read'],
      })
      return route.fulfill({
        status: 400,
        json: { error: { code: 'invalid_scope', message: 'invalid API key scope' } },
      })
    }
    return route.fulfill({ json: { keys: [] } })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: 'API Key' }).click()
  await page.getByRole('button', { name: '创建 Key' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: 'invalid API key scope' }).first()).toBeVisible()
  await expect(page.getByText('仅显示一次')).toHaveCount(0)
  expect(createCalls).toBe(1)
})

test('instance refresh surfaces the invalid_id envelope', async ({ page }) => {
  let refreshCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/accounts/1/refresh', (route) => {
    refreshCalls += 1
    expect(route.request().method()).toBe('POST')
    return route.fulfill({
      status: 400,
      json: { error: { code: 'invalid_id', message: '无效 ID' } },
    })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '刷新实例' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '无效 ID' }).first()).toBeVisible()
  expect(refreshCalls).toBe(1)
})

test('settings API key revoke surfaces the invalid_id envelope', async ({ page }) => {
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
      status: 400,
      json: { error: { code: 'invalid_id', message: '无效 ID' } },
    })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: 'API Key' }).click()
  await page.getByRole('button', { name: '撤销' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '无效 ID' }).first()).toBeVisible()
  await expect(page.locator('.key-row')).toContainText('桌面小组件')
  expect(revokeCalls).toBe(1)
})

test('admin passkey delete surfaces the invalid_id envelope', async ({ page }) => {
  const existing = { id: 8, name: '办公室电脑', created_at: new Date().toISOString() }
  let deleteCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/admin/passkeys', (route) => route.fulfill({ json: { passkeys: [existing] } }))
  await page.route('**/api/v1/admin/passkeys/**', (route) => {
    deleteCalls += 1
    expect(route.request().method()).toBe('DELETE')
    return route.fulfill({
      status: 400,
      json: { error: { code: 'invalid_id', message: '无效 ID' } },
    })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '管理员' }).click()
  await page.getByRole('button', { name: '删除 Passkey' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '无效 ID' }).first()).toBeVisible()
  await expect(page.locator('.passkey-row')).toContainText('办公室电脑')
  expect(deleteCalls).toBe(1)
})

test('settings email test surfaces the invalid_channel envelope', async ({ page }) => {
  let testCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/notifications/test/email', (route) => {
    testCalls += 1
    expect(route.request().method()).toBe('POST')
    return route.fulfill({
      status: 400,
      json: { error: { code: 'invalid_channel', message: 'invalid notification channel' } },
    })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: '发送测试' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: 'invalid notification channel' }).first()).toBeVisible()
  expect(testCalls).toBe(1)
})

test('settings telegram test surfaces the invalid_channel envelope', async ({ page }) => {
  let testCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/notifications/test/telegram', (route) => {
    testCalls += 1
    expect(route.request().method()).toBe('POST')
    return route.fulfill({
      status: 400,
      json: { error: { code: 'invalid_channel', message: 'invalid notification channel' } },
    })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: 'Telegram' }).click()
  await page.getByRole('button', { name: '发送测试' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: 'invalid notification channel' }).first()).toBeVisible()
  expect(testCalls).toBe(1)
})

test('settings webhook test surfaces the invalid_channel envelope', async ({ page }) => {
  let testCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/notifications/test/webhook', (route) => {
    testCalls += 1
    expect(route.request().method()).toBe('POST')
    return route.fulfill({
      status: 400,
      json: { error: { code: 'invalid_channel', message: 'invalid notification channel' } },
    })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: 'Webhook' }).click()
  await page.getByRole('button', { name: '发送测试' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: 'invalid notification channel' }).first()).toBeVisible()
  expect(testCalls).toBe(1)
})

test('settings save surfaces the forbidden envelope', async ({ page }) => {
  let saveCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/config', (route) => {
    if (route.request().method() === 'PUT') {
      saveCalls += 1
      return route.fulfill({
        status: 403,
        json: { error: { code: 'forbidden', message: 'API Key 权限不足' } },
      })
    }
    return route.fulfill({ json: dashboardConfig })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: 'API Key 权限不足' }).first()).toBeVisible()
  expect(saveCalls).toBe(1)
})

test('instance start surfaces the forbidden envelope', async ({ page }) => {
  let startCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page, {
    ...dashboardStatus,
    accounts: [{ ...dashboardAccount, instance_status: 'Stopped' }],
  })
  await page.route('**/api/v1/accounts/1/actions/start', (route) => {
    startCalls += 1
    expect(route.request().method()).toBe('POST')
    return route.fulfill({
      status: 403,
      json: { error: { code: 'forbidden', message: 'API Key 权限不足' } },
    })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '开机' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: 'API Key 权限不足' }).first()).toBeVisible()
  expect(startCalls).toBe(1)
})

test('instance stop surfaces the forbidden envelope', async ({ page }) => {
  let stopCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/accounts/1/actions/stop', (route) => {
    stopCalls += 1
    expect(route.request().method()).toBe('POST')
    return route.fulfill({
      status: 403,
      json: { error: { code: 'forbidden', message: 'API Key 权限不足' } },
    })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '关机' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: 'API Key 权限不足' }).first()).toBeVisible()
  expect(stopCalls).toBe(1)
})

test('settings save surfaces the not_found envelope', async ({ page }) => {
  let saveCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/config', (route) => {
    if (route.request().method() === 'PUT') {
      saveCalls += 1
      return route.fulfill({
        status: 404,
        json: { error: { code: 'not_found', message: '接口不存在' } },
      })
    }
    return route.fulfill({ json: dashboardConfig })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '接口不存在' }).first()).toBeVisible()
  expect(saveCalls).toBe(1)
})

test('instance start surfaces the not_found envelope', async ({ page }) => {
  let startCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page, {
    ...dashboardStatus,
    accounts: [{ ...dashboardAccount, instance_status: 'Stopped' }],
  })
  await page.route('**/api/v1/accounts/1/actions/start', (route) => {
    startCalls += 1
    expect(route.request().method()).toBe('POST')
    return route.fulfill({
      status: 404,
      json: { error: { code: 'not_found', message: '接口不存在' } },
    })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '开机' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '接口不存在' }).first()).toBeVisible()
  expect(startCalls).toBe(1)
})

test('instance stop surfaces the not_found envelope', async ({ page }) => {
  let stopCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/accounts/1/actions/stop', (route) => {
    stopCalls += 1
    expect(route.request().method()).toBe('POST')
    return route.fulfill({
      status: 404,
      json: { error: { code: 'not_found', message: '接口不存在' } },
    })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '关机' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '接口不存在' }).first()).toBeVisible()
  expect(stopCalls).toBe(1)
})

test('admin password update surfaces the invalid_request envelope', async ({ page }) => {
  let updateCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/admin/passkeys', (route) => route.fulfill({ json: { passkeys: [] } }))
  await page.route('**/api/v1/admin/password', (route) => {
    updateCalls += 1
    expect(route.request().method()).toBe('PUT')
    return route.fulfill({
      status: 400,
      json: { error: { code: 'invalid_request', message: '请求体无效' } },
    })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '管理员' }).click()
  await page.getByLabel('当前密码').fill(TEST_PASSWORD)
  await page.getByLabel('新密码', { exact: true }).fill('Rotated-Password-42!')
  await page.getByLabel('确认新密码').fill('Rotated-Password-42!')
  await page.getByRole('button', { name: '保存新密码' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '请求体无效' }).first()).toBeVisible()
  await expect(page.getByRole('heading', { name: '管理员设置' })).toBeVisible()
  expect(updateCalls).toBe(1)
})

test('settings API key create surfaces the empty name api_key_failed envelope', async ({ page }) => {
  let createCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/api-keys', (route) => {
    if (route.request().method() === 'POST') {
      createCalls += 1
      return route.fulfill({
        status: 400,
        json: { error: { code: 'api_key_failed', message: 'API Key 名称和权限不能为空' } },
      })
    }
    return route.fulfill({ json: { keys: [] } })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: 'API Key' }).click()
  await page.getByRole('button', { name: '创建 Key' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: 'API Key 名称和权限不能为空' }).first()).toBeVisible()
  await expect(page.getByText('仅显示一次')).toHaveCount(0)
  expect(createCalls).toBe(1)
})

test('settings API key create surfaces the invalid_request envelope', async ({ page }) => {
  let createCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/api-keys', (route) => {
    if (route.request().method() === 'POST') {
      createCalls += 1
      return route.fulfill({
        status: 400,
        json: { error: { code: 'invalid_request', message: '请求体无效' } },
      })
    }
    return route.fulfill({ json: { keys: [] } })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: 'API Key' }).click()
  await page.getByRole('button', { name: '创建 Key' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '请求体无效' }).first()).toBeVisible()
  await expect(page.getByText('仅显示一次')).toHaveCount(0)
  expect(createCalls).toBe(1)
})

test('wizard surfaces the invalid_request envelope and stays on install', async ({ page }) => {
  await mockInitStatus(page, false)
  await page.route('**/api/v1/setup', (route) => route.fulfill({
    status: 400,
    json: { error: { code: 'invalid_request', message: '请求体无效' } },
  }))

  await page.goto('/')
  const passwords = page.locator('input[type="password"]')
  await passwords.nth(0).fill(TEST_PASSWORD)
  await passwords.nth(1).fill(TEST_PASSWORD)
  await page.getByRole('button', { name: '继续' }).click()
  await page.getByRole('button', { name: '继续' }).click()
  await page.getByRole('button', { name: '完成安装' }).click()
  await expect(page.getByText('请求体无效')).toBeVisible()
  await expect(page.getByRole('heading', { name: '连接云端实例' })).toBeVisible()
})

test('wizard surfaces the session_failed envelope and stays on install', async ({ page }) => {
  await mockInitStatus(page, false)
  await page.route('**/api/v1/setup', (route) => route.fulfill({
    status: 500,
    json: { error: { code: 'session_failed', message: '无法创建会话' } },
  }))

  await page.goto('/')
  const passwords = page.locator('input[type="password"]')
  await passwords.nth(0).fill(TEST_PASSWORD)
  await passwords.nth(1).fill(TEST_PASSWORD)
  await page.getByRole('button', { name: '继续' }).click()
  await page.getByRole('button', { name: '继续' }).click()
  await page.getByRole('button', { name: '完成安装' }).click()
  await expect(page.getByText('无法创建会话')).toBeVisible()
  await expect(page.getByRole('heading', { name: '连接云端实例' })).toBeVisible()
})

test('settings save surfaces the live invalid shutdown mode envelope', async ({ page }) => {
  let saveCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/config', (route) => {
    if (route.request().method() === 'PUT') {
      saveCalls += 1
      return route.fulfill({
        status: 400,
        json: { error: { code: 'config_failed', message: 'invalid shutdown mode' } },
      })
    }
    return route.fulfill({ json: dashboardConfig })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: 'invalid shutdown mode' }).first()).toBeVisible()
  expect(saveCalls).toBe(1)
})

test('settings save surfaces the live invalid threshold action envelope', async ({ page }) => {
  let saveCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/config', (route) => {
    if (route.request().method() === 'PUT') {
      saveCalls += 1
      return route.fulfill({
        status: 400,
        json: { error: { code: 'config_failed', message: 'invalid threshold action' } },
      })
    }
    return route.fulfill({ json: dashboardConfig })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: 'invalid threshold action' }).first()).toBeVisible()
  expect(saveCalls).toBe(1)
})

test('settings save surfaces the live api interval envelope', async ({ page }) => {
  let saveCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/config', (route) => {
    if (route.request().method() === 'PUT') {
      saveCalls += 1
      return route.fulfill({
        status: 400,
        json: { error: { code: 'config_failed', message: 'api interval must be between 30 and 86400 seconds' } },
      })
    }
    return route.fulfill({ json: dashboardConfig })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: 'api interval must be between 30 and 86400 seconds' }).first()).toBeVisible()
  expect(saveCalls).toBe(1)
})

test('wizard surfaces the live invalid shutdown mode setup_failed envelope', async ({ page }) => {
  await mockInitStatus(page, false)
  await page.route('**/api/v1/setup', (route) => route.fulfill({
    status: 400,
    json: { error: { code: 'setup_failed', message: 'invalid shutdown mode' } },
  }))

  await page.goto('/')
  const passwords = page.locator('input[type="password"]')
  await passwords.nth(0).fill(TEST_PASSWORD)
  await passwords.nth(1).fill(TEST_PASSWORD)
  await page.getByRole('button', { name: '继续' }).click()
  await page.getByRole('button', { name: '继续' }).click()
  await page.getByRole('button', { name: '完成安装' }).click()
  await expect(page.getByText('invalid shutdown mode')).toBeVisible()
  await expect(page.getByRole('heading', { name: '连接云端实例' })).toBeVisible()
})

test('wizard surfaces the live invalid threshold action setup_failed envelope', async ({ page }) => {
  await mockInitStatus(page, false)
  await page.route('**/api/v1/setup', (route) => route.fulfill({
    status: 400,
    json: { error: { code: 'setup_failed', message: 'invalid threshold action' } },
  }))

  await page.goto('/')
  const passwords = page.locator('input[type="password"]')
  await passwords.nth(0).fill(TEST_PASSWORD)
  await passwords.nth(1).fill(TEST_PASSWORD)
  await page.getByRole('button', { name: '继续' }).click()
  await page.getByRole('button', { name: '继续' }).click()
  await page.getByRole('button', { name: '完成安装' }).click()
  await expect(page.getByText('invalid threshold action')).toBeVisible()
  await expect(page.getByRole('heading', { name: '连接云端实例' })).toBeVisible()
})

test('wizard surfaces the live api interval setup_failed envelope', async ({ page }) => {
  await mockInitStatus(page, false)
  await page.route('**/api/v1/setup', (route) => route.fulfill({
    status: 400,
    json: { error: { code: 'setup_failed', message: 'api interval must be between 30 and 86400 seconds' } },
  }))

  await page.goto('/')
  const passwords = page.locator('input[type="password"]')
  await passwords.nth(0).fill(TEST_PASSWORD)
  await passwords.nth(1).fill(TEST_PASSWORD)
  await page.getByRole('button', { name: '继续' }).click()
  await page.getByRole('button', { name: '继续' }).click()
  await page.getByRole('button', { name: '完成安装' }).click()
  await expect(page.getByText('api interval must be between 30 and 86400 seconds')).toBeVisible()
  await expect(page.getByRole('heading', { name: '连接云端实例' })).toBeVisible()
})

test('wizard surfaces the live short administrator password setup_failed envelope', async ({ page }) => {
  await mockInitStatus(page, false)
  await page.route('**/api/v1/setup', (route) => route.fulfill({
    status: 400,
    json: { error: { code: 'setup_failed', message: 'administrator password must be at least 10 characters' } },
  }))

  await page.goto('/')
  const passwords = page.locator('input[type="password"]')
  await passwords.nth(0).fill(TEST_PASSWORD)
  await passwords.nth(1).fill(TEST_PASSWORD)
  await page.getByRole('button', { name: '继续' }).click()
  await page.getByRole('button', { name: '继续' }).click()
  await page.getByRole('button', { name: '完成安装' }).click()
  await expect(page.getByText('administrator password must be at least 10 characters')).toBeVisible()
  await expect(page.getByRole('heading', { name: '连接云端实例' })).toBeVisible()
})

test('wizard surfaces the live missing administrator password setup_failed envelope', async ({ page }) => {
  await mockInitStatus(page, false)
  await page.route('**/api/v1/setup', (route) => route.fulfill({
    status: 400,
    json: { error: { code: 'setup_failed', message: 'administrator password is required' } },
  }))

  await page.goto('/')
  const passwords = page.locator('input[type="password"]')
  await passwords.nth(0).fill(TEST_PASSWORD)
  await passwords.nth(1).fill(TEST_PASSWORD)
  await page.getByRole('button', { name: '继续' }).click()
  await page.getByRole('button', { name: '继续' }).click()
  await page.getByRole('button', { name: '完成安装' }).click()
  await expect(page.getByText('administrator password is required')).toBeVisible()
  await expect(page.getByRole('heading', { name: '连接云端实例' })).toBeVisible()
})

test('instance start surfaces the csrf_failed envelope', async ({ page }) => {
  let startCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page, {
    ...dashboardStatus,
    accounts: [{ ...dashboardAccount, instance_status: 'Stopped' }],
  })
  await page.route('**/api/v1/accounts/1/actions/start', (route) => {
    startCalls += 1
    expect(route.request().method()).toBe('POST')
    return route.fulfill({
      status: 403,
      json: { error: { code: 'csrf_failed', message: 'CSRF 校验失败' } },
    })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '开机' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: 'CSRF 校验失败' }).first()).toBeVisible()
  expect(startCalls).toBe(1)
})

test('instance stop surfaces the csrf_failed envelope', async ({ page }) => {
  let stopCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/accounts/1/actions/stop', (route) => {
    stopCalls += 1
    expect(route.request().method()).toBe('POST')
    return route.fulfill({
      status: 403,
      json: { error: { code: 'csrf_failed', message: 'CSRF 校验失败' } },
    })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '关机' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: 'CSRF 校验失败' }).first()).toBeVisible()
  expect(stopCalls).toBe(1)
})

test('settings API key create surfaces the csrf_failed envelope', async ({ page }) => {
  let createCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/api-keys', (route) => {
    if (route.request().method() === 'POST') {
      createCalls += 1
      return route.fulfill({
        status: 403,
        json: { error: { code: 'csrf_failed', message: 'CSRF 校验失败' } },
      })
    }
    return route.fulfill({ json: { keys: [] } })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: 'API Key' }).click()
  await page.getByRole('button', { name: '创建 Key' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: 'CSRF 校验失败' }).first()).toBeVisible()
  await expect(page.getByText('仅显示一次')).toHaveCount(0)
  expect(createCalls).toBe(1)
})

test('settings email test surfaces the csrf_failed envelope', async ({ page }) => {
  let testCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/notifications/test/email', (route) => {
    testCalls += 1
    expect(route.request().method()).toBe('POST')
    return route.fulfill({
      status: 403,
      json: { error: { code: 'csrf_failed', message: 'CSRF 校验失败' } },
    })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: '发送测试' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: 'CSRF 校验失败' }).first()).toBeVisible()
  expect(testCalls).toBe(1)
})

test('settings telegram test surfaces the csrf_failed envelope', async ({ page }) => {
  let testCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/notifications/test/telegram', (route) => {
    testCalls += 1
    expect(route.request().method()).toBe('POST')
    return route.fulfill({
      status: 403,
      json: { error: { code: 'csrf_failed', message: 'CSRF 校验失败' } },
    })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: 'Telegram' }).click()
  await page.getByRole('button', { name: '发送测试' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: 'CSRF 校验失败' }).first()).toBeVisible()
  expect(testCalls).toBe(1)
})

test('settings webhook test surfaces the csrf_failed envelope', async ({ page }) => {
  let testCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/notifications/test/webhook', (route) => {
    testCalls += 1
    expect(route.request().method()).toBe('POST')
    return route.fulfill({
      status: 403,
      json: { error: { code: 'csrf_failed', message: 'CSRF 校验失败' } },
    })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: 'Webhook' }).click()
  await page.getByRole('button', { name: '发送测试' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: 'CSRF 校验失败' }).first()).toBeVisible()
  expect(testCalls).toBe(1)
})

test('instance refresh surfaces the csrf_failed envelope', async ({ page }) => {
  let refreshCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/accounts/1/refresh', (route) => {
    refreshCalls += 1
    expect(route.request().method()).toBe('POST')
    return route.fulfill({
      status: 403,
      json: { error: { code: 'csrf_failed', message: 'CSRF 校验失败' } },
    })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '刷新实例' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: 'CSRF 校验失败' }).first()).toBeVisible()
  expect(refreshCalls).toBe(1)
})

test('settings API key revoke surfaces the csrf_failed envelope', async ({ page }) => {
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
      status: 403,
      json: { error: { code: 'csrf_failed', message: 'CSRF 校验失败' } },
    })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: 'API Key' }).click()
  await page.getByRole('button', { name: '撤销' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: 'CSRF 校验失败' }).first()).toBeVisible()
  await expect(page.locator('.key-row')).toContainText('桌面小组件')
  expect(revokeCalls).toBe(1)
})

test('admin passkey delete surfaces the csrf_failed envelope', async ({ page }) => {
  const existing = { id: 8, name: '办公室电脑', created_at: new Date().toISOString() }
  let deleteCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/admin/passkeys', (route) => route.fulfill({ json: { passkeys: [existing] } }))
  await page.route('**/api/v1/admin/passkeys/**', (route) => {
    deleteCalls += 1
    expect(route.request().method()).toBe('DELETE')
    return route.fulfill({
      status: 403,
      json: { error: { code: 'csrf_failed', message: 'CSRF 校验失败' } },
    })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '管理员' }).click()
  await page.getByRole('button', { name: '删除 Passkey' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: 'CSRF 校验失败' }).first()).toBeVisible()
  await expect(page.locator('.passkey-row')).toContainText('办公室电脑')
  expect(deleteCalls).toBe(1)
})

test('admin password update surfaces the csrf_failed envelope', async ({ page }) => {
  let updateCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/admin/passkeys', (route) => route.fulfill({ json: { passkeys: [] } }))
  await page.route('**/api/v1/admin/password', (route) => {
    updateCalls += 1
    expect(route.request().method()).toBe('PUT')
    return route.fulfill({
      status: 403,
      json: { error: { code: 'csrf_failed', message: 'CSRF 校验失败' } },
    })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '管理员' }).click()
  await page.getByLabel('当前密码').fill(TEST_PASSWORD)
  await page.getByLabel('新密码', { exact: true }).fill('Rotated-Password-42!')
  await page.getByLabel('确认新密码').fill('Rotated-Password-42!')
  await page.getByRole('button', { name: '保存新密码' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: 'CSRF 校验失败' }).first()).toBeVisible()
  await expect(page.getByRole('heading', { name: '管理员设置' })).toBeVisible()
  expect(updateCalls).toBe(1)
})

test('log clear surfaces the csrf_failed envelope', async ({ page }) => {
  let clearCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/logs**', (route) => {
    if (route.request().method() === 'DELETE') {
      clearCalls += 1
      return route.fulfill({
        status: 403,
        json: { error: { code: 'csrf_failed', message: 'CSRF 校验失败' } },
      })
    }
    return route.fulfill({ json: { logs: [{ id: 1, type: 'audit', message: '保留日志', created_at: new Date().toISOString() }] } })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '日志' }).click()
  await expect(page.getByText('保留日志')).toBeVisible()
  await page.getByRole('button', { name: '清空' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: 'CSRF 校验失败' }).first()).toBeVisible()
  await expect(page.getByText('保留日志')).toBeVisible()
  expect(clearCalls).toBe(1)
})

test('log clear surfaces the forbidden envelope', async ({ page }) => {
  let clearCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/logs**', (route) => {
    if (route.request().method() === 'DELETE') {
      clearCalls += 1
      return route.fulfill({
        status: 403,
        json: { error: { code: 'forbidden', message: 'API Key 权限不足' } },
      })
    }
    return route.fulfill({ json: { logs: [{ id: 1, type: 'audit', message: '保留日志', created_at: new Date().toISOString() }] } })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '日志' }).click()
  await expect(page.getByText('保留日志')).toBeVisible()
  await page.getByRole('button', { name: '清空' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: 'API Key 权限不足' }).first()).toBeVisible()
  await expect(page.getByText('保留日志')).toBeVisible()
  expect(clearCalls).toBe(1)
})

test('log clear surfaces the not_found envelope', async ({ page }) => {
  let clearCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/logs**', (route) => {
    if (route.request().method() === 'DELETE') {
      clearCalls += 1
      return route.fulfill({
        status: 404,
        json: { error: { code: 'not_found', message: '接口不存在' } },
      })
    }
    return route.fulfill({ json: { logs: [{ id: 1, type: 'audit', message: '保留日志', created_at: new Date().toISOString() }] } })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '日志' }).click()
  await expect(page.getByText('保留日志')).toBeVisible()
  await page.getByRole('button', { name: '清空' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '接口不存在' }).first()).toBeVisible()
  await expect(page.getByText('保留日志')).toBeVisible()
  expect(clearCalls).toBe(1)
})

test('settings webhook variable picker posts from a scrubbed GET', async ({ page }) => {
  const configured = {
    ...dashboardConfig,
    notifications: {
      ...dashboardConfig.notifications,
      webhook: liveGetWebhook({
        enabled: true,
        method: 'POST',
        request_type: 'JSON',
        headers_configured: true,
        url_configured: true,
        body_configured: true,
      }),
    },
  }
  let savedWebhook: Record<string, unknown> | undefined
  await mockInitStatus(page, true)
  await mockDashboardReads(page, dashboardStatus, configured)
  await page.route('**/api/v1/config', async (route) => {
    if (route.request().method() === 'PUT') {
      const payload = JSON.parse(route.request().postData() || '{}') as { notifications?: { webhook?: Record<string, unknown> } }
      expectKnownKeys(payload, CONFIG_OBJECT_KEYS)
      savedWebhook = payload.notifications?.webhook
      return route.fulfill({ json: { success: true } })
    }
    return route.fulfill({ json: configured })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: 'Webhook' }).click()
  await expect(page.getByLabel('Body 模板 · 已配置')).toHaveValue('')
  await page.getByTitle('插入 #TITLE#').click()
  await expect(page.getByLabel('Body 模板 · 已配置')).toHaveValue('#TITLE#')
  await expect(page.getByText('__clear__')).toHaveCount(0)
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.getByText('配置已安全保存')).toBeVisible()
  expect(savedWebhook).toMatchObject({
    enabled: true,
    body: '#TITLE#',
    body_configured: true,
  })
  expect(savedWebhook).not.toHaveProperty('headers')
  expect(savedWebhook).not.toHaveProperty('url')
  expect(JSON.stringify(savedWebhook)).not.toContain('__clear__')
})

test('settings webhook variable picker exposes live replacement aliases', async ({ page }) => {
  const configured = {
    ...dashboardConfig,
    notifications: {
      ...dashboardConfig.notifications,
      webhook: liveGetWebhook({
        enabled: true,
        method: 'POST',
        request_type: 'JSON',
        body_configured: true,
      }),
    },
  }
  let savedWebhook: Record<string, unknown> | undefined
  await mockInitStatus(page, true)
  await mockDashboardReads(page, dashboardStatus, configured)
  await page.route('**/api/v1/config', async (route) => {
    if (route.request().method() === 'PUT') {
      const payload = JSON.parse(route.request().postData() || '{}') as { notifications?: { webhook?: Record<string, unknown> } }
      expectKnownKeys(payload, CONFIG_OBJECT_KEYS)
      savedWebhook = payload.notifications?.webhook
      return route.fulfill({ json: { success: true } })
    }
    return route.fulfill({ json: configured })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: 'Webhook' }).click()
  for (const token of ['#TITLE#', '#MSG#', '#ACCOUNT#', '#ACCOUNT_ID#', '#TRAFFIC#', '#TRAFFIC_GB#', '#MAX_TRAFFIC#', '#THRESHOLD_PERCENT#', '#INSTANCE#', '#STATUS#', '#TYPE#', '#CREATED_AT#', '#TIME#']) {
    await expect(page.getByTitle(`插入 ${token}`)).toBeVisible()
  }
  await page.getByTitle('插入 #TIME#').click()
  await expect(page.getByLabel('Body 模板 · 已配置')).toHaveValue('#TIME#')
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.getByText('配置已安全保存')).toBeVisible()
  expect(savedWebhook).toMatchObject({ body: '#TIME#' })
  expect(JSON.stringify(savedWebhook)).not.toContain('__clear__')
})

test('settings webhook variable picker inserts live aliases sequentially', async ({ page }) => {
  const configured = {
    ...dashboardConfig,
    notifications: {
      ...dashboardConfig.notifications,
      webhook: liveGetWebhook({
        enabled: true,
        method: 'POST',
        request_type: 'JSON',
        body_configured: true,
      }),
    },
  }
  let savedWebhook: Record<string, unknown> | undefined
  await mockInitStatus(page, true)
  await mockDashboardReads(page, dashboardStatus, configured)
  await page.route('**/api/v1/config', async (route) => {
    if (route.request().method() === 'PUT') {
      const payload = JSON.parse(route.request().postData() || '{}') as { notifications?: { webhook?: Record<string, unknown> } }
      expectKnownKeys(payload, CONFIG_OBJECT_KEYS)
      savedWebhook = payload.notifications?.webhook
      return route.fulfill({ json: { success: true } })
    }
    return route.fulfill({ json: configured })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: 'Webhook' }).click()
  await expect(page.getByLabel('Body 模板 · 已配置')).toHaveValue('')
  await page.getByTitle('插入 #ACCOUNT_ID#').click()
  await expect(page.getByLabel('Body 模板 · 已配置')).toHaveValue('#ACCOUNT_ID#')
  await page.getByTitle('插入 #TRAFFIC_GB#').click()
  await expect(page.getByLabel('Body 模板 · 已配置')).toHaveValue('#ACCOUNT_ID#\n#TRAFFIC_GB#')
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.getByText('配置已安全保存')).toBeVisible()
  expect(savedWebhook).toMatchObject({ body: '#ACCOUNT_ID#\n#TRAFFIC_GB#' })
  expect(JSON.stringify(savedWebhook)).not.toContain('__clear__')
})

test('settings webhook variable picker inserts threshold and time aliases', async ({ page }) => {
  const configured = {
    ...dashboardConfig,
    notifications: {
      ...dashboardConfig.notifications,
      webhook: liveGetWebhook({
        enabled: true,
        method: 'POST',
        request_type: 'JSON',
        body_configured: true,
      }),
    },
  }
  let savedWebhook: Record<string, unknown> | undefined
  await mockInitStatus(page, true)
  await mockDashboardReads(page, dashboardStatus, configured)
  await page.route('**/api/v1/config', async (route) => {
    if (route.request().method() === 'PUT') {
      const payload = JSON.parse(route.request().postData() || '{}') as { notifications?: { webhook?: Record<string, unknown> } }
      expectKnownKeys(payload, CONFIG_OBJECT_KEYS)
      savedWebhook = payload.notifications?.webhook
      return route.fulfill({ json: { success: true } })
    }
    return route.fulfill({ json: configured })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: 'Webhook' }).click()
  await page.getByTitle('插入 #THRESHOLD_PERCENT#').click()
  await expect(page.getByLabel('Body 模板 · 已配置')).toHaveValue('#THRESHOLD_PERCENT#')
  await page.getByTitle('插入 #TIME#').click()
  await expect(page.getByLabel('Body 模板 · 已配置')).toHaveValue('#THRESHOLD_PERCENT#\n#TIME#')
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.getByText('配置已安全保存')).toBeVisible()
  expect(savedWebhook).toMatchObject({ body: '#THRESHOLD_PERCENT#\n#TIME#' })
  expect(JSON.stringify(savedWebhook)).not.toContain('__clear__')
})

test('settings save surfaces the live too many accounts envelope', async ({ page }) => {
  let saveCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/config', (route) => {
    if (route.request().method() === 'PUT') {
      saveCalls += 1
      return route.fulfill({
        status: 400,
        json: { error: { code: 'config_failed', message: 'too many accounts' } },
      })
    }
    return route.fulfill({ json: dashboardConfig })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: 'too many accounts' }).first()).toBeVisible()
  expect(saveCalls).toBe(1)
})

test('wizard surfaces the live too many accounts setup_failed envelope', async ({ page }) => {
  await mockInitStatus(page, false)
  await page.route('**/api/v1/setup', (route) => route.fulfill({
    status: 400,
    json: { error: { code: 'setup_failed', message: 'too many accounts' } },
  }))

  await page.goto('/')
  const passwords = page.locator('input[type="password"]')
  await passwords.nth(0).fill(TEST_PASSWORD)
  await passwords.nth(1).fill(TEST_PASSWORD)
  await page.getByRole('button', { name: '继续' }).click()
  await page.getByRole('button', { name: '继续' }).click()
  await page.getByRole('button', { name: '完成安装' }).click()
  await expect(page.getByText('too many accounts')).toBeVisible()
  await expect(page.getByRole('heading', { name: '连接云端实例' })).toBeVisible()
})

test('settings add instance stops at the live account cap', async ({ page }) => {
  const cappedConfig = {
    ...dashboardConfig,
    accounts: Array.from({ length: MAX_ACCOUNTS }, (_, index) => ({
      ...dashboardConfig.accounts[0],
      id: index + 1,
      access_key_id: `LTAI5cap${index + 1}`,
      instance_id: `i-cap${index + 1}`,
      remark: `节点 ${index + 1}`,
      secret_configured: true,
    })),
  }
  await mockInitStatus(page, true)
  await mockDashboardReads(page, dashboardStatus, cappedConfig)

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '实例', exact: true }).click()
  await expect(page.locator('.account-editor')).toHaveCount(MAX_ACCOUNTS)
  await expect(page.getByRole('button', { name: '添加实例' })).toBeDisabled()
})

test('settings save surfaces the live account remark too long envelope', async ({ page }) => {
  let saveCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/config', (route) => {
    if (route.request().method() === 'PUT') {
      saveCalls += 1
      return route.fulfill({
        status: 400,
        json: { error: { code: 'config_failed', message: 'account remark is too long' } },
      })
    }
    return route.fulfill({ json: dashboardConfig })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: 'account remark is too long' }).first()).toBeVisible()
  expect(saveCalls).toBe(1)
})

test('wizard surfaces the live account remark too long setup_failed envelope', async ({ page }) => {
  await mockInitStatus(page, false)
  await page.route('**/api/v1/setup', (route) => route.fulfill({
    status: 400,
    json: { error: { code: 'setup_failed', message: 'account remark is too long' } },
  }))

  await page.goto('/')
  const passwords = page.locator('input[type="password"]')
  await passwords.nth(0).fill(TEST_PASSWORD)
  await passwords.nth(1).fill(TEST_PASSWORD)
  await page.getByRole('button', { name: '继续' }).click()
  await page.getByRole('button', { name: '继续' }).click()
  await page.getByRole('button', { name: '完成安装' }).click()
  await expect(page.getByText('account remark is too long')).toBeVisible()
  await expect(page.getByRole('heading', { name: '连接云端实例' })).toBeVisible()
})

test('settings account remark posts at the live rune cap', async ({ page }) => {
  let saveCalls = 0
  let remark = ''
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/config', async (route) => {
    if (route.request().method() === 'PUT') {
      saveCalls += 1
      const body = JSON.parse(route.request().postData() || '{}') as { accounts?: { remark?: string }[] }
      expectKnownKeys(body as Record<string, unknown>, CONFIG_OBJECT_KEYS)
      remark = body.accounts?.[0]?.remark || ''
      return route.fulfill({ json: { success: true } })
    }
    return route.fulfill({ json: dashboardConfig })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '实例', exact: true }).click()
  await page.getByLabel('备注').fill(`${'备'.repeat(MAX_ACCOUNT_REMARK_RUNES)}超`)
  await expect(page.getByLabel('备注')).toHaveValue('备'.repeat(MAX_ACCOUNT_REMARK_RUNES))
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.getByText('配置已安全保存')).toBeVisible()
  expect(saveCalls).toBe(1)
  expect([...remark]).toHaveLength(MAX_ACCOUNT_REMARK_RUNES)
  expect(remark).toBe('备'.repeat(MAX_ACCOUNT_REMARK_RUNES))
})

test('settings save surfaces the live account max traffic envelope', async ({ page }) => {
  let saveCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/config', (route) => {
    if (route.request().method() === 'PUT') {
      saveCalls += 1
      return route.fulfill({
        status: 400,
        json: { error: { code: 'config_failed', message: 'account max traffic is invalid' } },
      })
    }
    return route.fulfill({ json: dashboardConfig })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: 'account max traffic is invalid' }).first()).toBeVisible()
  expect(saveCalls).toBe(1)
})

test('wizard surfaces the live account max traffic setup_failed envelope', async ({ page }) => {
  await mockInitStatus(page, false)
  await page.route('**/api/v1/setup', (route) => route.fulfill({
    status: 400,
    json: { error: { code: 'setup_failed', message: 'account max traffic is invalid' } },
  }))

  await page.goto('/')
  const passwords = page.locator('input[type="password"]')
  await passwords.nth(0).fill(TEST_PASSWORD)
  await passwords.nth(1).fill(TEST_PASSWORD)
  await page.getByRole('button', { name: '继续' }).click()
  await page.getByRole('button', { name: '继续' }).click()
  await page.getByRole('button', { name: '完成安装' }).click()
  await expect(page.getByText('account max traffic is invalid')).toBeVisible()
  await expect(page.getByRole('heading', { name: '连接云端实例' })).toBeVisible()
})

test('settings account max traffic posts at the live GB cap', async ({ page }) => {
  let saveCalls = 0
  let maxTraffic = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/config', async (route) => {
    if (route.request().method() === 'PUT') {
      saveCalls += 1
      const body = JSON.parse(route.request().postData() || '{}') as { accounts?: { max_traffic?: number }[] }
      expectKnownKeys(body as Record<string, unknown>, CONFIG_OBJECT_KEYS)
      maxTraffic = Number(body.accounts?.[0]?.max_traffic)
      return route.fulfill({ json: { success: true } })
    }
    return route.fulfill({ json: dashboardConfig })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '实例', exact: true }).click()
  await page.getByLabel('流量额度').fill(String(MAX_ACCOUNT_TRAFFIC_GB + 1))
  await expect(page.getByLabel('流量额度')).toHaveValue(String(MAX_ACCOUNT_TRAFFIC_GB))
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.getByText('配置已安全保存')).toBeVisible()
  expect(saveCalls).toBe(1)
  expect(maxTraffic).toBe(MAX_ACCOUNT_TRAFFIC_GB)
})

test('settings save surfaces the live account access_key_id invalid envelope', async ({ page }) => {
  let saveCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/config', (route) => {
    if (route.request().method() === 'PUT') {
      saveCalls += 1
      return route.fulfill({
        status: 400,
        json: { error: { code: 'config_failed', message: 'account access_key_id is invalid' } },
      })
    }
    return route.fulfill({ json: dashboardConfig })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: 'account access_key_id is invalid' }).first()).toBeVisible()
  expect(saveCalls).toBe(1)
})

test('wizard surfaces the live account access_key_id invalid setup_failed envelope', async ({ page }) => {
  await mockInitStatus(page, false)
  await page.route('**/api/v1/setup', (route) => route.fulfill({
    status: 400,
    json: { error: { code: 'setup_failed', message: 'account access_key_id is invalid' } },
  }))

  await page.goto('/')
  const passwords = page.locator('input[type="password"]')
  await passwords.nth(0).fill(TEST_PASSWORD)
  await passwords.nth(1).fill(TEST_PASSWORD)
  await page.getByRole('button', { name: '继续' }).click()
  await page.getByRole('button', { name: '继续' }).click()
  await page.getByRole('button', { name: '完成安装' }).click()
  await expect(page.getByText('account access_key_id is invalid')).toBeVisible()
  await expect(page.getByRole('heading', { name: '连接云端实例' })).toBeVisible()
})

test('settings access_key_id posts at the live character cap', async ({ page }) => {
  let saveCalls = 0
  let accessKeyID = ''
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/config', async (route) => {
    if (route.request().method() === 'PUT') {
      saveCalls += 1
      const body = JSON.parse(route.request().postData() || '{}') as { accounts?: { access_key_id?: string }[] }
      expectKnownKeys(body as Record<string, unknown>, CONFIG_OBJECT_KEYS)
      accessKeyID = body.accounts?.[0]?.access_key_id || ''
      return route.fulfill({ json: { success: true } })
    }
    return route.fulfill({ json: dashboardConfig })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '实例', exact: true }).click()
  await page.getByLabel('AccessKey ID').fill(`${'A'.repeat(MAX_ACCESS_KEY_ID_CHARS)}!超`)
  await expect(page.getByLabel('AccessKey ID')).toHaveValue('A'.repeat(MAX_ACCESS_KEY_ID_CHARS))
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.getByText('配置已安全保存')).toBeVisible()
  expect(saveCalls).toBe(1)
  expect(accessKeyID).toBe('A'.repeat(MAX_ACCESS_KEY_ID_CHARS))
})

test('settings save surfaces the live account instance_id invalid envelope', async ({ page }) => {
  let saveCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/config', (route) => {
    if (route.request().method() === 'PUT') {
      saveCalls += 1
      return route.fulfill({
        status: 400,
        json: { error: { code: 'config_failed', message: 'account instance_id is invalid' } },
      })
    }
    return route.fulfill({ json: dashboardConfig })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: 'account instance_id is invalid' }).first()).toBeVisible()
  expect(saveCalls).toBe(1)
})

test('wizard surfaces the live account instance_id invalid setup_failed envelope', async ({ page }) => {
  await mockInitStatus(page, false)
  await page.route('**/api/v1/setup', (route) => route.fulfill({
    status: 400,
    json: { error: { code: 'setup_failed', message: 'account instance_id is invalid' } },
  }))

  await page.goto('/')
  const passwords = page.locator('input[type="password"]')
  await passwords.nth(0).fill(TEST_PASSWORD)
  await passwords.nth(1).fill(TEST_PASSWORD)
  await page.getByRole('button', { name: '继续' }).click()
  await page.getByRole('button', { name: '继续' }).click()
  await page.getByRole('button', { name: '完成安装' }).click()
  await expect(page.getByText('account instance_id is invalid')).toBeVisible()
  await expect(page.getByRole('heading', { name: '连接云端实例' })).toBeVisible()
})

test('settings instance_id posts at the live character cap', async ({ page }) => {
  let saveCalls = 0
  let instanceID = ''
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/config', async (route) => {
    if (route.request().method() === 'PUT') {
      saveCalls += 1
      const body = JSON.parse(route.request().postData() || '{}') as { accounts?: { instance_id?: string }[] }
      expectKnownKeys(body as Record<string, unknown>, CONFIG_OBJECT_KEYS)
      instanceID = body.accounts?.[0]?.instance_id || ''
      return route.fulfill({ json: { success: true } })
    }
    return route.fulfill({ json: dashboardConfig })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '实例', exact: true }).click()
  await page.getByLabel('实例 ID').fill(`i-${'a'.repeat(MAX_INSTANCE_ID_CHARS)}!超`)
  await expect(page.getByLabel('实例 ID')).toHaveValue(`i-${'a'.repeat(MAX_INSTANCE_ID_CHARS - 2)}`)
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.getByText('配置已安全保存')).toBeVisible()
  expect(saveCalls).toBe(1)
  expect(instanceID).toBe(`i-${'a'.repeat(MAX_INSTANCE_ID_CHARS - 2)}`)
  expect(instanceID).toHaveLength(MAX_INSTANCE_ID_CHARS)
})

test('settings save surfaces the live account schedule time envelope', async ({ page }) => {
  let saveCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/config', (route) => {
    if (route.request().method() === 'PUT') {
      saveCalls += 1
      return route.fulfill({
        status: 400,
        json: { error: { code: 'config_failed', message: 'account schedule time is invalid' } },
      })
    }
    return route.fulfill({ json: dashboardConfig })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: 'account schedule time is invalid' }).first()).toBeVisible()
  expect(saveCalls).toBe(1)
})

test('wizard surfaces the live account schedule time setup_failed envelope', async ({ page }) => {
  await mockInitStatus(page, false)
  await page.route('**/api/v1/setup', (route) => route.fulfill({
    status: 400,
    json: { error: { code: 'setup_failed', message: 'account schedule time is invalid' } },
  }))

  await page.goto('/')
  const passwords = page.locator('input[type="password"]')
  await passwords.nth(0).fill(TEST_PASSWORD)
  await passwords.nth(1).fill(TEST_PASSWORD)
  await page.getByRole('button', { name: '继续' }).click()
  await page.getByRole('button', { name: '继续' }).click()
  await page.getByRole('button', { name: '完成安装' }).click()
  await expect(page.getByText('account schedule time is invalid')).toBeVisible()
  await expect(page.getByRole('heading', { name: '连接云端实例' })).toBeVisible()
})

test('settings schedule clocks post the live 15:04 contract', async ({ page }) => {
  let saveCalls = 0
  let account: { start_time?: string; stop_time?: string } | undefined
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/config', async (route) => {
    if (route.request().method() === 'PUT') {
      saveCalls += 1
      const body = JSON.parse(route.request().postData() || '{}') as { accounts?: typeof account[] }
      expectKnownKeys(body as Record<string, unknown>, CONFIG_OBJECT_KEYS)
      account = body.accounts?.[0]
      return route.fulfill({ json: { success: true } })
    }
    return route.fulfill({ json: dashboardConfig })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '实例', exact: true }).click()
  await page.getByText('每日定时开关机', { exact: true }).click()
  expect(liveScheduleClock('07:05:00')).toBe('07:05')
  expect(liveScheduleClock('18:40:00.5')).toBe('18:40')
  await page.getByLabel('开机时间').fill('07:05')
  await page.getByLabel('关机时间').fill('18:40')
  await expect(page.getByLabel('开机时间')).toHaveValue('07:05')
  await expect(page.getByLabel('关机时间')).toHaveValue('18:40')
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.getByText('配置已安全保存')).toBeVisible()
  expect(saveCalls).toBe(1)
  expect(account).toMatchObject({ start_time: '07:05', stop_time: '18:40' })
})

test('settings save surfaces the live notification identity envelope', async ({ page }) => {
  let saveCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/config', (route) => {
    if (route.request().method() === 'PUT') {
      saveCalls += 1
      return route.fulfill({
        status: 400,
        json: { error: { code: 'config_failed', message: 'notification identity is too long' } },
      })
    }
    return route.fulfill({ json: dashboardConfig })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: 'notification identity is too long' }).first()).toBeVisible()
  expect(saveCalls).toBe(1)
})

test('wizard surfaces the live notification identity setup_failed envelope', async ({ page }) => {
  await mockInitStatus(page, false)
  await page.route('**/api/v1/setup', (route) => route.fulfill({
    status: 400,
    json: { error: { code: 'setup_failed', message: 'notification identity is too long' } },
  }))

  await page.goto('/')
  const passwords = page.locator('input[type="password"]')
  await passwords.nth(0).fill(TEST_PASSWORD)
  await passwords.nth(1).fill(TEST_PASSWORD)
  await page.getByRole('button', { name: '继续' }).click()
  await page.getByRole('button', { name: '继续' }).click()
  await page.getByRole('button', { name: '完成安装' }).click()
  await expect(page.getByText('notification identity is too long')).toBeVisible()
  await expect(page.getByRole('heading', { name: '连接云端实例' })).toBeVisible()
})

test('settings telegram chat id posts at the live rune cap', async ({ page }) => {
  let saveCalls = 0
  let chatID = ''
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/config', async (route) => {
    if (route.request().method() === 'PUT') {
      saveCalls += 1
      const body = JSON.parse(route.request().postData() || '{}') as { notifications?: { telegram?: { chat_id?: string } } }
      expectKnownKeys(body as Record<string, unknown>, CONFIG_OBJECT_KEYS)
      chatID = body.notifications?.telegram?.chat_id || ''
      return route.fulfill({ json: { success: true } })
    }
    return route.fulfill({ json: dashboardConfig })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: 'Telegram' }).click()
  await page.getByLabel('Chat ID').fill(`${'1'.repeat(MAX_TELEGRAM_CHAT_RUNES)}超`)
  await expect(page.getByLabel('Chat ID')).toHaveValue('1'.repeat(MAX_TELEGRAM_CHAT_RUNES))
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.getByText('配置已安全保存')).toBeVisible()
  expect(saveCalls).toBe(1)
  expect([...chatID]).toHaveLength(MAX_TELEGRAM_CHAT_RUNES)
  expect(chatID).toBe('1'.repeat(MAX_TELEGRAM_CHAT_RUNES))
})

test('settings email identity posts at the live rune cap', async ({ page }) => {
  let saveCalls = 0
  let email: { to?: string; username?: string } | undefined
  const overflow = `${'a'.repeat(MAX_NOTIFY_EMAIL_RUNES)}超`
  const capped = 'a'.repeat(MAX_NOTIFY_EMAIL_RUNES)
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/config', async (route) => {
    if (route.request().method() === 'PUT') {
      saveCalls += 1
      const body = JSON.parse(route.request().postData() || '{}') as { notifications?: { email?: { to?: string; username?: string } } }
      expectKnownKeys(body as Record<string, unknown>, CONFIG_OBJECT_KEYS)
      email = body.notifications?.email
      return route.fulfill({ json: { success: true } })
    }
    return route.fulfill({ json: dashboardConfig })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: 'Email' }).click()
  await page.getByLabel('接收邮箱').fill(overflow)
  await page.getByLabel('用户名').fill(overflow)
  await expect(page.getByLabel('接收邮箱')).toHaveValue(capped)
  await expect(page.getByLabel('用户名')).toHaveValue(capped)
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.getByText('配置已安全保存')).toBeVisible()
  expect(saveCalls).toBe(1)
  expect([...email?.to || '']).toHaveLength(MAX_NOTIFY_EMAIL_RUNES)
  expect([...email?.username || '']).toHaveLength(MAX_NOTIFY_EMAIL_RUNES)
  expect(email).toMatchObject({ to: capped, username: capped })
})

test('settings save surfaces the live notification port envelope', async ({ page }) => {
  let saveCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/config', (route) => {
    if (route.request().method() === 'PUT') {
      saveCalls += 1
      return route.fulfill({
        status: 400,
        json: { error: { code: 'config_failed', message: 'notification port is invalid' } },
      })
    }
    return route.fulfill({ json: dashboardConfig })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: 'notification port is invalid' }).first()).toBeVisible()
  expect(saveCalls).toBe(1)
})

test('wizard surfaces the live notification port setup_failed envelope', async ({ page }) => {
  await mockInitStatus(page, false)
  await page.route('**/api/v1/setup', (route) => route.fulfill({
    status: 400,
    json: { error: { code: 'setup_failed', message: 'notification port is invalid' } },
  }))

  await page.goto('/')
  const passwords = page.locator('input[type="password"]')
  await passwords.nth(0).fill(TEST_PASSWORD)
  await passwords.nth(1).fill(TEST_PASSWORD)
  await page.getByRole('button', { name: '继续' }).click()
  await page.getByRole('button', { name: '继续' }).click()
  await page.getByRole('button', { name: '完成安装' }).click()
  await expect(page.getByText('notification port is invalid')).toBeVisible()
  await expect(page.getByRole('heading', { name: '连接云端实例' })).toBeVisible()
})

test('settings email port posts at the live TCP cap', async ({ page }) => {
  let saveCalls = 0
  let port = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/config', async (route) => {
    if (route.request().method() === 'PUT') {
      saveCalls += 1
      const body = JSON.parse(route.request().postData() || '{}') as { notifications?: { email?: { port?: number } } }
      expectKnownKeys(body as Record<string, unknown>, CONFIG_OBJECT_KEYS)
      port = Number(body.notifications?.email?.port)
      return route.fulfill({ json: { success: true } })
    }
    return route.fulfill({ json: dashboardConfig })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: 'Email' }).click()
  await page.getByLabel('端口').fill(String(MAX_NOTIFY_TCP_PORT + 1))
  await expect(page.getByLabel('端口')).toHaveValue(String(MAX_NOTIFY_TCP_PORT))
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.getByText('配置已安全保存')).toBeVisible()
  expect(saveCalls).toBe(1)
  expect(port).toBe(MAX_NOTIFY_TCP_PORT)
})

test('settings telegram proxy port posts at the live TCP cap', async ({ page }) => {
  let saveCalls = 0
  let proxyPort = ''
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/config', async (route) => {
    if (route.request().method() === 'PUT') {
      saveCalls += 1
      const body = JSON.parse(route.request().postData() || '{}') as { notifications?: { telegram?: { proxy_port?: string } } }
      expectKnownKeys(body as Record<string, unknown>, CONFIG_OBJECT_KEYS)
      proxyPort = body.notifications?.telegram?.proxy_port || ''
      return route.fulfill({ json: { success: true } })
    }
    return route.fulfill({ json: dashboardConfig })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: 'Telegram' }).click()
  await page.getByLabel('代理类型').click()
  await page.getByRole('option', { name: 'SOCKS5' }).click()
  await page.getByLabel('代理端口').fill(String(MAX_NOTIFY_TCP_PORT + 1))
  await expect(page.getByLabel('代理端口')).toHaveValue(String(MAX_NOTIFY_TCP_PORT))
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.getByText('配置已安全保存')).toBeVisible()
  expect(saveCalls).toBe(1)
  expect(proxyPort).toBe(String(MAX_NOTIFY_TCP_PORT))
})

test('settings save surfaces the live notification header envelope', async ({ page }) => {
  let saveCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/config', (route) => {
    if (route.request().method() === 'PUT') {
      saveCalls += 1
      return route.fulfill({
        status: 400,
        json: { error: { code: 'config_failed', message: 'notification header fields must not contain line breaks' } },
      })
    }
    return route.fulfill({ json: dashboardConfig })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: 'notification header fields must not contain line breaks' }).first()).toBeVisible()
  expect(saveCalls).toBe(1)
})

test('wizard surfaces the live notification header setup_failed envelope', async ({ page }) => {
  await mockInitStatus(page, false)
  await page.route('**/api/v1/setup', (route) => route.fulfill({
    status: 400,
    json: { error: { code: 'setup_failed', message: 'notification header fields must not contain line breaks' } },
  }))

  await page.goto('/')
  const passwords = page.locator('input[type="password"]')
  await passwords.nth(0).fill(TEST_PASSWORD)
  await passwords.nth(1).fill(TEST_PASSWORD)
  await page.getByRole('button', { name: '继续' }).click()
  await page.getByRole('button', { name: '继续' }).click()
  await page.getByRole('button', { name: '完成安装' }).click()
  await expect(page.getByText('notification header fields must not contain line breaks')).toBeVisible()
  await expect(page.getByRole('heading', { name: '连接云端实例' })).toBeVisible()
})

test('settings webhook headers strip live header line breaks', async ({ page }) => {
  let saveCalls = 0
  let headers = ''
  const broken = '{"X-Test":"a\nb"}'
  const stripped = liveNotifyHeaderText(broken)
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/config', async (route) => {
    if (route.request().method() === 'PUT') {
      saveCalls += 1
      const body = JSON.parse(route.request().postData() || '{}') as { notifications?: { webhook?: { headers?: string } } }
      expectKnownKeys(body as Record<string, unknown>, CONFIG_OBJECT_KEYS)
      headers = body.notifications?.webhook?.headers || ''
      return route.fulfill({ json: { success: true } })
    }
    return route.fulfill({ json: dashboardConfig })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: 'Webhook' }).click()
  await page.getByLabel(/自定义 Headers/).fill(broken)
  await expect(page.getByLabel(/自定义 Headers/)).toHaveValue(stripped)
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.getByText('配置已安全保存')).toBeVisible()
  expect(saveCalls).toBe(1)
  expect(headers).toBe(stripped)
  expect(headers).not.toMatch(/[\r\n\u0000]/)
})

test('settings telegram chat id strips live header line breaks', async ({ page }) => {
  let saveCalls = 0
  let chatID = ''
  const broken = '-1001\n超'
  const stripped = liveNotifyHeaderText(broken)
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/config', async (route) => {
    if (route.request().method() === 'PUT') {
      saveCalls += 1
      const body = JSON.parse(route.request().postData() || '{}') as { notifications?: { telegram?: { chat_id?: string } } }
      expectKnownKeys(body as Record<string, unknown>, CONFIG_OBJECT_KEYS)
      chatID = body.notifications?.telegram?.chat_id || ''
      return route.fulfill({ json: { success: true } })
    }
    return route.fulfill({ json: dashboardConfig })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: 'Telegram' }).click()
  await page.getByLabel('Chat ID').evaluate((input, value) => {
    const field = input as HTMLInputElement
    Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value')?.set?.call(field, value)
    field.dispatchEvent(new Event('input', { bubbles: true }))
  }, broken)
  await expect(page.getByLabel('Chat ID')).toHaveValue(stripped)
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.getByText('配置已安全保存')).toBeVisible()
  expect(saveCalls).toBe(1)
  expect(chatID).toBe(stripped)
  expect(chatID).not.toMatch(/[\r\n\u0000]/)
})

test('settings email identity strips live header line breaks', async ({ page }) => {
  let saveCalls = 0
  let email: { to?: string; username?: string } | undefined
  const brokenTo = 'ops@example.invalid\n'
  const brokenUser = 'ops\ruser'
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/config', async (route) => {
    if (route.request().method() === 'PUT') {
      saveCalls += 1
      const body = JSON.parse(route.request().postData() || '{}') as { notifications?: { email?: { to?: string; username?: string } } }
      expectKnownKeys(body as Record<string, unknown>, CONFIG_OBJECT_KEYS)
      email = body.notifications?.email
      return route.fulfill({ json: { success: true } })
    }
    return route.fulfill({ json: dashboardConfig })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: 'Email' }).click()
  await page.getByLabel('接收邮箱').evaluate((input, value) => {
    const field = input as HTMLInputElement
    Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value')?.set?.call(field, value)
    field.dispatchEvent(new Event('input', { bubbles: true }))
  }, brokenTo)
  await page.getByLabel('用户名').evaluate((input, value) => {
    const field = input as HTMLInputElement
    Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value')?.set?.call(field, value)
    field.dispatchEvent(new Event('input', { bubbles: true }))
  }, brokenUser)
  await expect(page.getByLabel('接收邮箱')).toHaveValue(liveNotifyHeaderText(brokenTo))
  await expect(page.getByLabel('用户名')).toHaveValue(liveNotifyHeaderText(brokenUser))
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.getByText('配置已安全保存')).toBeVisible()
  expect(saveCalls).toBe(1)
  expect(email).toMatchObject({
    to: liveNotifyHeaderText(brokenTo),
    username: liveNotifyHeaderText(brokenUser),
  })
})

test('settings save surfaces the live notification payload envelope', async ({ page }) => {
  let saveCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/config', (route) => {
    if (route.request().method() === 'PUT') {
      saveCalls += 1
      return route.fulfill({
        status: 400,
        json: { error: { code: 'config_failed', message: 'notification payload is too long' } },
      })
    }
    return route.fulfill({ json: dashboardConfig })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: 'notification payload is too long' }).first()).toBeVisible()
  expect(saveCalls).toBe(1)
})

test('wizard surfaces the live notification payload setup_failed envelope', async ({ page }) => {
  await mockInitStatus(page, false)
  await page.route('**/api/v1/setup', (route) => route.fulfill({
    status: 400,
    json: { error: { code: 'setup_failed', message: 'notification payload is too long' } },
  }))

  await page.goto('/')
  const passwords = page.locator('input[type="password"]')
  await passwords.nth(0).fill(TEST_PASSWORD)
  await passwords.nth(1).fill(TEST_PASSWORD)
  await page.getByRole('button', { name: '继续' }).click()
  await page.getByRole('button', { name: '继续' }).click()
  await page.getByRole('button', { name: '完成安装' }).click()
  await expect(page.getByText('notification payload is too long')).toBeVisible()
  await expect(page.getByRole('heading', { name: '连接云端实例' })).toBeVisible()
})

test('settings webhook headers post at the live rune cap', async ({ page }) => {
  let saveCalls = 0
  let headers = ''
  const overflow = `${'h'.repeat(MAX_WEBHOOK_HEADERS_RUNES)}超`
  const capped = 'h'.repeat(MAX_WEBHOOK_HEADERS_RUNES)
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/config', async (route) => {
    if (route.request().method() === 'PUT') {
      saveCalls += 1
      const body = JSON.parse(route.request().postData() || '{}') as { notifications?: { webhook?: { headers?: string } } }
      expectKnownKeys(body as Record<string, unknown>, CONFIG_OBJECT_KEYS)
      headers = body.notifications?.webhook?.headers || ''
      return route.fulfill({ json: { success: true } })
    }
    return route.fulfill({ json: dashboardConfig })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: 'Webhook' }).click()
  await page.getByLabel(/自定义 Headers/).fill(overflow)
  await expect(page.getByLabel(/自定义 Headers/)).toHaveValue(capped)
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.getByText('配置已安全保存')).toBeVisible()
  expect(saveCalls).toBe(1)
  expect([...headers]).toHaveLength(MAX_WEBHOOK_HEADERS_RUNES)
  expect(headers).toBe(capped)
})

test('settings webhook body posts at the live rune cap', async ({ page }) => {
  let saveCalls = 0
  let bodyText = ''
  const overflow = `${'b'.repeat(MAX_WEBHOOK_BODY_RUNES)}超`
  const capped = 'b'.repeat(MAX_WEBHOOK_BODY_RUNES)
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/config', async (route) => {
    if (route.request().method() === 'PUT') {
      saveCalls += 1
      const payload = JSON.parse(route.request().postData() || '{}') as { notifications?: { webhook?: { body?: string } } }
      expectKnownKeys(payload as Record<string, unknown>, CONFIG_OBJECT_KEYS)
      bodyText = payload.notifications?.webhook?.body || ''
      return route.fulfill({ json: { success: true } })
    }
    return route.fulfill({ json: dashboardConfig })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: 'Webhook' }).click()
  await page.getByLabel(/Body 模板/).fill(overflow)
  await expect(page.getByLabel(/Body 模板/)).toHaveValue(capped)
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.getByText('配置已安全保存')).toBeVisible()
  expect(saveCalls).toBe(1)
  expect([...bodyText]).toHaveLength(MAX_WEBHOOK_BODY_RUNES)
  expect(bodyText).toBe(capped)
})

test('settings webhook url posts at the live rune cap', async ({ page }) => {
  let saveCalls = 0
  let url = ''
  const overflow = `${'u'.repeat(MAX_NOTIFY_URL_RUNES)}超`
  const capped = 'u'.repeat(MAX_NOTIFY_URL_RUNES)
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/config', async (route) => {
    if (route.request().method() === 'PUT') {
      saveCalls += 1
      const payload = JSON.parse(route.request().postData() || '{}') as { notifications?: { webhook?: { url?: string } } }
      expectKnownKeys(payload as Record<string, unknown>, CONFIG_OBJECT_KEYS)
      url = payload.notifications?.webhook?.url || ''
      return route.fulfill({ json: { success: true } })
    }
    return route.fulfill({ json: dashboardConfig })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: 'Webhook' }).click()
  await page.getByLabel(/Webhook URL/).fill(overflow)
  await expect(page.getByLabel(/Webhook URL/)).toHaveValue(capped)
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.getByText('配置已安全保存')).toBeVisible()
  expect(saveCalls).toBe(1)
  expect([...url]).toHaveLength(MAX_NOTIFY_URL_RUNES)
  expect(url).toBe(capped)
})

test('settings telegram proxy url posts at the live rune cap', async ({ page }) => {
  let saveCalls = 0
  let proxyURL = ''
  const overflow = `${'u'.repeat(MAX_NOTIFY_URL_RUNES)}超`
  const capped = 'u'.repeat(MAX_NOTIFY_URL_RUNES)
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/config', async (route) => {
    if (route.request().method() === 'PUT') {
      saveCalls += 1
      const payload = JSON.parse(route.request().postData() || '{}') as { notifications?: { telegram?: { proxy_url?: string } } }
      expectKnownKeys(payload as Record<string, unknown>, CONFIG_OBJECT_KEYS)
      proxyURL = payload.notifications?.telegram?.proxy_url || ''
      return route.fulfill({ json: { success: true } })
    }
    return route.fulfill({ json: dashboardConfig })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: 'Telegram' }).click()
  await page.getByLabel('代理类型').click()
  await page.getByRole('option', { name: '自定义反代' }).click()
  await page.getByLabel(/反代 URL/).fill(overflow)
  await expect(page.getByLabel(/反代 URL/)).toHaveValue(capped)
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.getByText('配置已安全保存')).toBeVisible()
  expect(saveCalls).toBe(1)
  expect([...proxyURL]).toHaveLength(MAX_NOTIFY_URL_RUNES)
  expect(proxyURL).toBe(capped)
})

test('settings telegram token posts at the live secret rune cap', async ({ page }) => {
  let saveCalls = 0
  let token = ''
  const overflow = `${'t'.repeat(MAX_NOTIFY_SECRET_RUNES)}超`
  const capped = 't'.repeat(MAX_NOTIFY_SECRET_RUNES)
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/config', async (route) => {
    if (route.request().method() === 'PUT') {
      saveCalls += 1
      const payload = JSON.parse(route.request().postData() || '{}') as { notifications?: { telegram?: { token?: string } } }
      expectKnownKeys(payload as Record<string, unknown>, CONFIG_OBJECT_KEYS)
      token = payload.notifications?.telegram?.token || ''
      return route.fulfill({ json: { success: true } })
    }
    return route.fulfill({ json: dashboardConfig })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: 'Telegram' }).click()
  await page.getByLabel('Bot Token').fill(overflow)
  await expect(page.getByLabel('Bot Token')).toHaveValue(capped)
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.getByText('配置已安全保存')).toBeVisible()
  expect(saveCalls).toBe(1)
  expect([...token]).toHaveLength(MAX_NOTIFY_SECRET_RUNES)
  expect(token).toBe(capped)
})

test('settings email password posts at the live secret rune cap', async ({ page }) => {
  let saveCalls = 0
  let password = ''
  const overflow = `${'p'.repeat(MAX_NOTIFY_SECRET_RUNES)}超`
  const capped = 'p'.repeat(MAX_NOTIFY_SECRET_RUNES)
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/config', async (route) => {
    if (route.request().method() === 'PUT') {
      saveCalls += 1
      const payload = JSON.parse(route.request().postData() || '{}') as { notifications?: { email?: { password?: string } } }
      expectKnownKeys(payload as Record<string, unknown>, CONFIG_OBJECT_KEYS)
      password = payload.notifications?.email?.password || ''
      return route.fulfill({ json: { success: true } })
    }
    return route.fulfill({ json: dashboardConfig })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: 'Email' }).click()
  await page.getByLabel('密码', { exact: true }).fill(overflow)
  await expect(page.getByLabel('密码', { exact: true })).toHaveValue(capped)
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.getByText('配置已安全保存')).toBeVisible()
  expect(saveCalls).toBe(1)
  expect([...password]).toHaveLength(MAX_NOTIFY_SECRET_RUNES)
  expect(password).toBe(capped)
})

test('settings telegram proxy password posts at the live secret rune cap', async ({ page }) => {
  let saveCalls = 0
  let proxyPass = ''
  const overflow = `${'p'.repeat(MAX_NOTIFY_SECRET_RUNES)}超`
  const capped = 'p'.repeat(MAX_NOTIFY_SECRET_RUNES)
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/config', async (route) => {
    if (route.request().method() === 'PUT') {
      saveCalls += 1
      const payload = JSON.parse(route.request().postData() || '{}') as { notifications?: { telegram?: { proxy_pass?: string } } }
      expectKnownKeys(payload as Record<string, unknown>, CONFIG_OBJECT_KEYS)
      proxyPass = payload.notifications?.telegram?.proxy_pass || ''
      return route.fulfill({ json: { success: true } })
    }
    return route.fulfill({ json: dashboardConfig })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: 'Telegram' }).click()
  await page.getByLabel('代理类型').click()
  await page.getByRole('option', { name: 'SOCKS5' }).click()
  await page.getByLabel('代理密码').fill(overflow)
  await expect(page.getByLabel('代理密码')).toHaveValue(capped)
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.getByText('配置已安全保存')).toBeVisible()
  expect(saveCalls).toBe(1)
  expect([...proxyPass]).toHaveLength(MAX_NOTIFY_SECRET_RUNES)
  expect(proxyPass).toBe(capped)
})

test('settings telegram proxy user posts at the live secret rune cap', async ({ page }) => {
  let saveCalls = 0
  let proxyUser = ''
  const overflow = `${'u'.repeat(MAX_NOTIFY_SECRET_RUNES)}超`
  const capped = 'u'.repeat(MAX_NOTIFY_SECRET_RUNES)
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/config', async (route) => {
    if (route.request().method() === 'PUT') {
      saveCalls += 1
      const payload = JSON.parse(route.request().postData() || '{}') as { notifications?: { telegram?: { proxy_user?: string } } }
      expectKnownKeys(payload as Record<string, unknown>, CONFIG_OBJECT_KEYS)
      proxyUser = payload.notifications?.telegram?.proxy_user || ''
      return route.fulfill({ json: { success: true } })
    }
    return route.fulfill({ json: dashboardConfig })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: 'Telegram' }).click()
  await page.getByLabel('代理类型').click()
  await page.getByRole('option', { name: 'SOCKS5' }).click()
  await page.getByLabel('代理账号').fill(overflow)
  await expect(page.getByLabel('代理账号')).toHaveValue(capped)
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.getByText('配置已安全保存')).toBeVisible()
  expect(saveCalls).toBe(1)
  expect([...proxyUser]).toHaveLength(MAX_NOTIFY_SECRET_RUNES)
  expect(proxyUser).toBe(capped)
})

test('settings webhook secret posts at the live secret rune cap', async ({ page }) => {
  let saveCalls = 0
  let secret = ''
  const overflow = `${'s'.repeat(MAX_NOTIFY_SECRET_RUNES)}超`
  const capped = 's'.repeat(MAX_NOTIFY_SECRET_RUNES)
  const configured = {
    ...dashboardConfig,
    notifications: {
      ...dashboardConfig.notifications,
      webhook: liveGetWebhook({ provider: 'dingtalk' }),
    },
  }
  await mockInitStatus(page, true)
  await mockDashboardReads(page, dashboardStatus, configured)
  await page.route('**/api/v1/config', async (route) => {
    if (route.request().method() === 'PUT') {
      saveCalls += 1
      const payload = JSON.parse(route.request().postData() || '{}') as { notifications?: { webhook?: { secret?: string } } }
      expectKnownKeys(payload as Record<string, unknown>, CONFIG_OBJECT_KEYS)
      secret = payload.notifications?.webhook?.secret || ''
      return route.fulfill({ json: { success: true } })
    }
    return route.fulfill({ json: configured })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: 'Webhook' }).click()
  await page.getByLabel('钉钉加签密钥').fill(overflow)
  await expect(page.getByLabel('钉钉加签密钥')).toHaveValue(capped)
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.getByText('配置已安全保存')).toBeVisible()
  expect(saveCalls).toBe(1)
  expect([...secret]).toHaveLength(MAX_NOTIFY_SECRET_RUNES)
  expect(secret).toBe(capped)
})

test('settings email host posts at the live dial-host rune cap', async ({ page }) => {
  let saveCalls = 0
  let host = ''
  const overflow = `${'h'.repeat(MAX_NOTIFY_DIAL_HOST_RUNES)}超`
  const capped = 'h'.repeat(MAX_NOTIFY_DIAL_HOST_RUNES)
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/config', async (route) => {
    if (route.request().method() === 'PUT') {
      saveCalls += 1
      const payload = JSON.parse(route.request().postData() || '{}') as { notifications?: { email?: { host?: string } } }
      expectKnownKeys(payload as Record<string, unknown>, CONFIG_OBJECT_KEYS)
      host = payload.notifications?.email?.host || ''
      return route.fulfill({ json: { success: true } })
    }
    return route.fulfill({ json: dashboardConfig })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: 'Email' }).click()
  await page.getByLabel('SMTP Host').fill(overflow)
  await expect(page.getByLabel('SMTP Host')).toHaveValue(capped)
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.getByText('配置已安全保存')).toBeVisible()
  expect(saveCalls).toBe(1)
  expect([...host]).toHaveLength(MAX_NOTIFY_DIAL_HOST_RUNES)
  expect(host).toBe(capped)
})

test('settings telegram proxy ip posts at the live dial-host rune cap', async ({ page }) => {
  let saveCalls = 0
  let proxyIP = ''
  const overflow = `${'h'.repeat(MAX_NOTIFY_DIAL_HOST_RUNES)}超`
  const capped = 'h'.repeat(MAX_NOTIFY_DIAL_HOST_RUNES)
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/config', async (route) => {
    if (route.request().method() === 'PUT') {
      saveCalls += 1
      const payload = JSON.parse(route.request().postData() || '{}') as { notifications?: { telegram?: { proxy_ip?: string } } }
      expectKnownKeys(payload as Record<string, unknown>, CONFIG_OBJECT_KEYS)
      proxyIP = payload.notifications?.telegram?.proxy_ip || ''
      return route.fulfill({ json: { success: true } })
    }
    return route.fulfill({ json: dashboardConfig })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: 'Telegram' }).click()
  await page.getByLabel('代理类型').click()
  await page.getByRole('option', { name: 'SOCKS5' }).click()
  await page.getByLabel('代理 IP').fill(overflow)
  await expect(page.getByLabel('代理 IP')).toHaveValue(capped)
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.getByText('配置已安全保存')).toBeVisible()
  expect(saveCalls).toBe(1)
  expect([...proxyIP]).toHaveLength(MAX_NOTIFY_DIAL_HOST_RUNES)
  expect(proxyIP).toBe(capped)
})

test('settings timezone posts at the live rune cap', async ({ page }) => {
  let saveCalls = 0
  let timezone = ''
  const overflow = `${'Z'.repeat(MAX_TIMEZONE_RUNES)}超`
  const capped = 'Z'.repeat(MAX_TIMEZONE_RUNES)
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/config', async (route) => {
    if (route.request().method() === 'PUT') {
      saveCalls += 1
      const payload = JSON.parse(route.request().postData() || '{}') as { timezone?: string }
      expectKnownKeys(payload as Record<string, unknown>, CONFIG_OBJECT_KEYS)
      timezone = payload.timezone || ''
      return route.fulfill({ json: { success: true } })
    }
    return route.fulfill({ json: dashboardConfig })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByLabel('系统时区').fill(overflow)
  await expect(page.getByLabel('系统时区')).toHaveValue(capped)
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.getByText('配置已安全保存')).toBeVisible()
  expect(saveCalls).toBe(1)
  expect([...timezone]).toHaveLength(MAX_TIMEZONE_RUNES)
  expect(timezone).toBe(capped)
})

test('wizard surfaces the live password is too long setup_failed envelope', async ({ page }) => {
  await mockInitStatus(page, false)
  await page.route('**/api/v1/setup', (route) => route.fulfill({
    status: 400,
    json: { error: { code: 'setup_failed', message: 'password is too long' } },
  }))

  await page.goto('/')
  const passwords = page.locator('input[type="password"]')
  await passwords.nth(0).fill(TEST_PASSWORD)
  await passwords.nth(1).fill(TEST_PASSWORD)
  await page.getByRole('button', { name: '继续' }).click()
  await page.getByRole('button', { name: '继续' }).click()
  await page.getByRole('button', { name: '完成安装' }).click()
  await expect(page.getByText('password is too long')).toBeVisible()
  await expect(page.getByRole('heading', { name: '连接云端实例' })).toBeVisible()
})

test('admin password update surfaces the live password too long envelope', async ({ page }) => {
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/admin/passkeys', (route) => route.fulfill({ json: { passkeys: [] } }))
  await page.route('**/api/v1/admin/password', (route) => {
    expect(route.request().method()).toBe('PUT')
    return route.fulfill({
      status: 400,
      json: { error: { code: 'invalid_password', message: '新密码过长' } },
    })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '管理员' }).click()
  await page.getByLabel('当前密码').fill(TEST_PASSWORD)
  await page.getByLabel('新密码', { exact: true }).fill(`${TEST_PASSWORD}extra`)
  await page.getByLabel('确认新密码').fill(`${TEST_PASSWORD}extra`)
  await page.getByRole('button', { name: '保存新密码' }).click()
  await expect(page.getByText('新密码过长')).toBeVisible()
  await expect(page.getByRole('heading', { name: '管理员设置' })).toBeVisible()
})

test('admin new password posts at the live rune cap', async ({ page }) => {
  let updateCalls = 0
  let newPassword = ''
  const overflow = `${'P'.repeat(MAX_PASSWORD_RUNES)}超`
  const capped = 'P'.repeat(MAX_PASSWORD_RUNES)
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/admin/passkeys', (route) => route.fulfill({ json: { passkeys: [] } }))
  await page.route('**/api/v1/admin/password', (route) => {
    updateCalls += 1
    const payload = JSON.parse(route.request().postData() || '{}') as { current_password?: string; new_password?: string }
    expect(payload.current_password).toBe(TEST_PASSWORD)
    newPassword = payload.new_password || ''
    return route.fulfill({ json: { success: true } })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '管理员' }).click()
  await page.getByLabel('当前密码').fill(TEST_PASSWORD)
  await page.getByLabel('新密码', { exact: true }).fill(overflow)
  await page.getByLabel('确认新密码').fill(overflow)
  await expect(page.getByLabel('新密码', { exact: true })).toHaveValue(capped)
  await expect(page.getByLabel('确认新密码')).toHaveValue(capped)
  await page.getByRole('button', { name: '保存新密码' }).click()
  await expect(page.getByText('管理员密码已更新')).toBeVisible()
  expect(updateCalls).toBe(1)
  expect([...newPassword]).toHaveLength(MAX_PASSWORD_RUNES)
  expect(newPassword).toBe(capped)
})

test('settings save surfaces the live account access_key_secret too long envelope', async ({ page }) => {
  let saveCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/config', (route) => {
    if (route.request().method() === 'PUT') {
      saveCalls += 1
      return route.fulfill({
        status: 400,
        json: { error: { code: 'config_failed', message: 'account access_key_secret is too long' } },
      })
    }
    return route.fulfill({ json: dashboardConfig })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: 'account access_key_secret is too long' }).first()).toBeVisible()
  expect(saveCalls).toBe(1)
})

test('wizard surfaces the live account access_key_secret too long setup_failed envelope', async ({ page }) => {
  await mockInitStatus(page, false)
  await page.route('**/api/v1/setup', (route) => route.fulfill({
    status: 400,
    json: { error: { code: 'setup_failed', message: 'account access_key_secret is too long' } },
  }))

  await page.goto('/')
  const passwords = page.locator('input[type="password"]')
  await passwords.nth(0).fill(TEST_PASSWORD)
  await passwords.nth(1).fill(TEST_PASSWORD)
  await page.getByRole('button', { name: '继续' }).click()
  await page.getByRole('button', { name: '继续' }).click()
  await page.getByRole('button', { name: '完成安装' }).click()
  await expect(page.getByText('account access_key_secret is too long')).toBeVisible()
  await expect(page.getByRole('heading', { name: '连接云端实例' })).toBeVisible()
})

test('settings access_key_secret posts at the live rune cap', async ({ page }) => {
  let saveCalls = 0
  let secret = ''
  const overflow = `${'s'.repeat(MAX_ACCESS_KEY_SECRET_RUNES)}超`
  const capped = 's'.repeat(MAX_ACCESS_KEY_SECRET_RUNES)
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/config', async (route) => {
    if (route.request().method() === 'PUT') {
      saveCalls += 1
      const payload = JSON.parse(route.request().postData() || '{}') as { accounts?: { access_key_secret?: string }[] }
      expectKnownKeys(payload as Record<string, unknown>, CONFIG_OBJECT_KEYS)
      secret = payload.accounts?.[0]?.access_key_secret || ''
      return route.fulfill({ json: { success: true } })
    }
    return route.fulfill({ json: dashboardConfig })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '实例', exact: true }).click()
  await page.getByLabel(/AccessKey Secret/).fill(overflow)
  await expect(page.getByLabel(/AccessKey Secret/)).toHaveValue(capped)
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.getByText('配置已安全保存')).toBeVisible()
  expect(saveCalls).toBe(1)
  expect([...secret]).toHaveLength(MAX_ACCESS_KEY_SECRET_RUNES)
  expect(secret).toBe(capped)
})

test('settings API key create surfaces the live too many api keys envelope', async ({ page }) => {
  let createCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/api-keys', (route) => {
    if (route.request().method() === 'POST') {
      createCalls += 1
      return route.fulfill({
        status: 400,
        json: { error: { code: 'api_key_failed', message: 'too many api keys' } },
      })
    }
    return route.fulfill({ json: { keys: [] } })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: 'API Key' }).click()
  await page.getByRole('button', { name: '创建 Key' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: 'too many api keys' }).first()).toBeVisible()
  expect(createCalls).toBe(1)
})

test('settings API key create stops at the live key cap', async ({ page }) => {
  const keys = Array.from({ length: MAX_API_KEYS }, (_, index) => ({
    id: index + 1,
    name: `key-${index + 1}`,
    scopes: ['widget:read'],
    created_at: new Date().toISOString(),
  }))
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/api-keys', (route) => route.fulfill({ json: { keys } }))

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: 'API Key' }).click()
  await expect(page.locator('.key-row')).toHaveCount(MAX_API_KEYS)
  await expect(page.getByRole('button', { name: '创建 Key' })).toBeDisabled()
})

test('settings save surfaces the live notification option envelope', async ({ page }) => {
  let saveCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/config', (route) => {
    if (route.request().method() === 'PUT') {
      saveCalls += 1
      return route.fulfill({
        status: 400,
        json: { error: { code: 'config_failed', message: 'notification option is invalid' } },
      })
    }
    return route.fulfill({ json: dashboardConfig })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: 'notification option is invalid' }).first()).toBeVisible()
  expect(saveCalls).toBe(1)
})

test('wizard surfaces the live notification option setup_failed envelope', async ({ page }) => {
  await mockInitStatus(page, false)
  await page.route('**/api/v1/setup', (route) => route.fulfill({
    status: 400,
    json: { error: { code: 'setup_failed', message: 'notification option is invalid' } },
  }))

  await page.goto('/')
  const passwords = page.locator('input[type="password"]')
  await passwords.nth(0).fill(TEST_PASSWORD)
  await passwords.nth(1).fill(TEST_PASSWORD)
  await page.getByRole('button', { name: '继续' }).click()
  await page.getByRole('button', { name: '继续' }).click()
  await page.getByRole('button', { name: '完成安装' }).click()
  await expect(page.getByText('notification option is invalid')).toBeVisible()
  await expect(page.getByRole('heading', { name: '连接云端实例' })).toBeVisible()
})

test('settings passkey create stays capped at the live passkey limit', async ({ page }) => {
  const passkeys = Array.from({ length: MAX_PASSKEYS }, (_, index) => ({
    id: index + 1,
    name: `device-${index + 1}`,
    created_at: new Date().toISOString(),
  }))
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/admin/passkeys', (route) => route.fulfill({ json: { passkeys } }))

  await page.goto('/')
  await page.getByRole('button', { name: '管理员' }).click()
  await expect(page.locator('.passkey-row')).toHaveCount(MAX_PASSKEYS)
  await expect(page.getByRole('button', { name: '创建 Passkey' })).toBeDisabled()
  await expect(page.getByText('Passkey 只能在 HTTPS 安全上下文中创建')).toBeVisible()
  await expect(page.getByText('尚未创建管理员 Passkey')).toHaveCount(0)
})

test('admin passkey name stops at the live rune cap', async ({ page }) => {
  const overflow = `${'N'.repeat(MAX_PASSKEY_NAME_RUNES)}超`
  const capped = 'N'.repeat(MAX_PASSKEY_NAME_RUNES)
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/admin/passkeys', (route) => route.fulfill({ json: { passkeys: [] } }))

  await page.goto('/')
  await page.getByRole('button', { name: '管理员' }).click()
  await page.getByLabel('设备名称').fill(overflow)
  await expect(page.getByLabel('设备名称')).toHaveValue(capped)
  await expect(page.getByRole('button', { name: '创建 Passkey' })).toBeDisabled()
  await expect(page.getByText('Passkey 只能在 HTTPS 安全上下文中创建')).toBeVisible()
})

test('settings API key name posts at the live rune cap', async ({ page }) => {
  let createCalls = 0
  let createdName = ''
  const overflow = `${'K'.repeat(MAX_API_KEY_NAME_RUNES)}超`
  const capped = 'K'.repeat(MAX_API_KEY_NAME_RUNES)
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/api-keys', (route) => {
    if (route.request().method() === 'POST') {
      createCalls += 1
      const payload = JSON.parse(route.request().postData() || '{}') as { name?: string; scopes?: string[] }
      createdName = payload.name || ''
      expect(payload.scopes).toEqual(['widget:read'])
      return route.fulfill({
        status: 201,
        json: {
          key: { id: 1, name: capped, scopes: ['widget:read'], created_at: new Date().toISOString() },
          token: 'cdt_test_token_once',
        },
      })
    }
    return route.fulfill({ json: { keys: [] } })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: 'API Key' }).click()
  await page.getByLabel('名称').fill(overflow)
  await expect(page.getByLabel('名称')).toHaveValue(capped)
  await page.getByRole('button', { name: '创建 Key' }).click()
  await expect(page.getByText('仅显示一次')).toBeVisible()
  expect(createCalls).toBe(1)
  expect([...createdName]).toHaveLength(MAX_API_KEY_NAME_RUNES)
  expect(createdName).toBe(capped)
})

test('settings save surfaces the live account region_id invalid envelope', async ({ page }) => {
  let saveCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/config', (route) => {
    if (route.request().method() === 'PUT') {
      saveCalls += 1
      return route.fulfill({
        status: 400,
        json: { error: { code: 'config_failed', message: 'account region_id is invalid' } },
      })
    }
    return route.fulfill({ json: dashboardConfig })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: 'account region_id is invalid' }).first()).toBeVisible()
  expect(saveCalls).toBe(1)
})

test('wizard surfaces the live account region_id invalid setup_failed envelope', async ({ page }) => {
  await mockInitStatus(page, false)
  await page.route('**/api/v1/setup', (route) => route.fulfill({
    status: 400,
    json: { error: { code: 'setup_failed', message: 'account region_id is invalid' } },
  }))

  await page.goto('/')
  const passwords = page.locator('input[type="password"]')
  await passwords.nth(0).fill(TEST_PASSWORD)
  await passwords.nth(1).fill(TEST_PASSWORD)
  await page.getByRole('button', { name: '继续' }).click()
  await page.getByRole('button', { name: '继续' }).click()
  await page.getByRole('button', { name: '完成安装' }).click()
  await expect(page.getByText('account region_id is invalid')).toBeVisible()
  await expect(page.getByRole('heading', { name: '连接云端实例' })).toBeVisible()
})

test('about settings surfaces the live internal_error envelope', async ({ page }) => {
  let infoCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/system/info**', (route) => {
    infoCalls += 1
    return route.fulfill({
      status: 500,
      json: { error: { code: 'internal_error', message: '服务暂时不可用' } },
    })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '关于' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '服务暂时不可用' }).first()).toBeVisible()
  expect(infoCalls).toBeGreaterThan(0)
})

test('about update check surfaces the live internal_error envelope', async ({ page }) => {
  let checkCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/system/info**', (route) => {
    const check = new URL(route.request().url()).searchParams.get('check') === '1'
    if (check) {
      checkCalls += 1
      return route.fulfill({
        status: 500,
        json: { error: { code: 'internal_error', message: '服务暂时不可用' } },
      })
    }
    return route.fulfill({ json: {
      version: 'v2.0.1',
      commit: 'abc1234',
      built_at: 'github-run-12345',
      repository: 'https://github.com/wang4386/CDT-Monitor',
      release_url: 'https://github.com/wang4386/CDT-Monitor/releases',
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
  await expect(page.getByText('当前版本')).toBeVisible()
  await page.getByRole('button', { name: '检查更新' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '服务暂时不可用' }).first()).toBeVisible()
  expect(checkCalls).toBe(1)
})

test('about update check falls back after the live check_error contract', async ({ page }) => {
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
    headers: { 'access-control-allow-origin': '*' },
    json: { tag_name: 'v2.0.3' },
  }))

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '关于' }).click()
  await page.getByRole('button', { name: '检查更新' }).click()
  await expect(page.getByText('已通过浏览器网络检查版本')).toBeVisible()
  await expect(page.getByText('GitHub 最新版本：v2.0.3')).toBeVisible()
  expect(checkCalls).toBe(1)
})

test('about settings surfaces the live unauthorized envelope', async ({ page }) => {
  let infoCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/system/info**', (route) => {
    infoCalls += 1
    return route.fulfill({
      status: 401,
      json: { error: { code: 'unauthorized', message: '请登录或提供有效 API Key' } },
    })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '关于' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '请登录或提供有效 API Key' }).first()).toBeVisible()
  expect(infoCalls).toBeGreaterThan(0)
})

test('about settings surfaces the live forbidden envelope', async ({ page }) => {
  let infoCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/system/info**', (route) => {
    infoCalls += 1
    return route.fulfill({
      status: 403,
      json: { error: { code: 'forbidden', message: 'API Key 权限不足' } },
    })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '关于' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: 'API Key 权限不足' }).first()).toBeVisible()
  expect(infoCalls).toBeGreaterThan(0)
})

test('about settings surfaces the live not_found envelope', async ({ page }) => {
  let infoCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/system/info**', (route) => {
    infoCalls += 1
    return route.fulfill({
      status: 404,
      json: { error: { code: 'not_found', message: '接口不存在' } },
    })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '关于' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '接口不存在' }).first()).toBeVisible()
  expect(infoCalls).toBeGreaterThan(0)
})

test('history chart surfaces the live unauthorized envelope', async ({ page }) => {
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/accounts/1/history', (route) => route.fulfill({
    status: 401,
    json: { error: { code: 'unauthorized', message: '请登录或提供有效 API Key' } },
  }))

  await page.goto('/')
  await page.getByRole('button', { name: '查看历史流量' }).click()
  await expect(page.getByRole('alert')).toContainText('请登录或提供有效 API Key')
  await expect(page.locator('.chart-area .recharts-wrapper')).toHaveCount(0)
})

test('history chart surfaces the live forbidden envelope', async ({ page }) => {
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/accounts/1/history', (route) => route.fulfill({
    status: 403,
    json: { error: { code: 'forbidden', message: 'API Key 权限不足' } },
  }))

  await page.goto('/')
  await page.getByRole('button', { name: '查看历史流量' }).click()
  await expect(page.getByRole('alert')).toContainText('API Key 权限不足')
  await expect(page.locator('.chart-area .recharts-wrapper')).toHaveCount(0)
})

test('history chart surfaces the live not_found envelope', async ({ page }) => {
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/accounts/1/history', (route) => route.fulfill({
    status: 404,
    json: { error: { code: 'not_found', message: '接口不存在' } },
  }))

  await page.goto('/')
  await page.getByRole('button', { name: '查看历史流量' }).click()
  await expect(page.getByRole('alert')).toContainText('接口不存在')
  await expect(page.locator('.chart-area .recharts-wrapper')).toHaveCount(0)
})

test('history chart surfaces the live invalid_id envelope', async ({ page }) => {
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/accounts/1/history', (route) => route.fulfill({
    status: 400,
    json: { error: { code: 'invalid_id', message: '无效 ID' } },
  }))

  await page.goto('/')
  await page.getByRole('button', { name: '查看历史流量' }).click()
  await expect(page.getByRole('alert')).toContainText('无效 ID')
  await expect(page.locator('.chart-area .recharts-wrapper')).toHaveCount(0)
})

test('history chart surfaces the live internal_error envelope', async ({ page }) => {
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/accounts/1/history', (route) => route.fulfill({
    status: 500,
    json: { error: { code: 'internal_error', message: '服务暂时不可用' } },
  }))

  await page.goto('/')
  await page.getByRole('button', { name: '查看历史流量' }).click()
  await expect(page.getByRole('alert')).toContainText('服务暂时不可用')
  await expect(page.locator('.chart-area .recharts-wrapper')).toHaveCount(0)
})

test('settings logs surface the live unauthorized envelope', async ({ page }) => {
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/logs**', (route) => route.fulfill({
    status: 401,
    json: { error: { code: 'unauthorized', message: '请登录或提供有效 API Key' } },
  }))

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '日志' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '请登录或提供有效 API Key' }).first()).toBeVisible()
  await expect(page.getByText('暂无日志')).toBeVisible()
  await expect(page.getByRole('heading', { name: '运行日志' })).toBeVisible()
})

test('settings logs surface the live forbidden envelope', async ({ page }) => {
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/logs**', (route) => route.fulfill({
    status: 403,
    json: { error: { code: 'forbidden', message: 'API Key 权限不足' } },
  }))

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '日志' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: 'API Key 权限不足' }).first()).toBeVisible()
  await expect(page.getByText('暂无日志')).toBeVisible()
  await expect(page.getByRole('heading', { name: '运行日志' })).toBeVisible()
})

test('settings logs surface the live not_found envelope', async ({ page }) => {
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/logs**', (route) => route.fulfill({
    status: 404,
    json: { error: { code: 'not_found', message: '接口不存在' } },
  }))

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '日志' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '接口不存在' }).first()).toBeVisible()
  await expect(page.getByText('暂无日志')).toBeVisible()
  await expect(page.getByRole('heading', { name: '运行日志' })).toBeVisible()
})

test('settings logs surface the live internal_error envelope', async ({ page }) => {
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/logs**', (route) => route.fulfill({
    status: 500,
    json: { error: { code: 'internal_error', message: '服务暂时不可用' } },
  }))

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '日志' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '服务暂时不可用' }).first()).toBeVisible()
  await expect(page.getByText('暂无日志')).toBeVisible()
  await expect(page.getByRole('heading', { name: '运行日志' })).toBeVisible()
})

test('settings API keys surface the live unauthorized envelope', async ({ page }) => {
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/api-keys', (route) => route.fulfill({
    status: 401,
    json: { error: { code: 'unauthorized', message: '请登录或提供有效 API Key' } },
  }))

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: 'API Key' }).click()
  await expect(page.locator('.inline-error')).toContainText('请登录或提供有效 API Key')
  await expect(page.getByRole('button', { name: '重试' })).toBeVisible()
  await expect(page.getByRole('heading', { name: 'API Key' })).toBeVisible()
})

test('settings API keys surface the live forbidden envelope', async ({ page }) => {
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/api-keys', (route) => route.fulfill({
    status: 403,
    json: { error: { code: 'forbidden', message: 'API Key 权限不足' } },
  }))

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: 'API Key' }).click()
  await expect(page.locator('.inline-error')).toContainText('API Key 权限不足')
  await expect(page.getByRole('button', { name: '重试' })).toBeVisible()
  await expect(page.getByRole('heading', { name: 'API Key' })).toBeVisible()
})

test('settings API keys surface the live not_found envelope', async ({ page }) => {
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/api-keys', (route) => route.fulfill({
    status: 404,
    json: { error: { code: 'not_found', message: '接口不存在' } },
  }))

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: 'API Key' }).click()
  await expect(page.locator('.inline-error')).toContainText('接口不存在')
  await expect(page.getByRole('button', { name: '重试' })).toBeVisible()
  await expect(page.getByRole('heading', { name: 'API Key' })).toBeVisible()
})

test('settings API keys surface the live internal_error envelope', async ({ page }) => {
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/api-keys', (route) => route.fulfill({
    status: 500,
    json: { error: { code: 'internal_error', message: '服务暂时不可用' } },
  }))

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: 'API Key' }).click()
  await expect(page.locator('.inline-error')).toContainText('服务暂时不可用')
  await expect(page.getByRole('button', { name: '重试' })).toBeVisible()
  await expect(page.getByRole('heading', { name: 'API Key' })).toBeVisible()
})

test('admin passkeys surface the live unauthorized envelope', async ({ page }) => {
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/admin/passkeys', (route) => route.fulfill({
    status: 401,
    json: { error: { code: 'unauthorized', message: '请登录或提供有效 API Key' } },
  }))

  await page.goto('/')
  await page.getByRole('button', { name: '管理员' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '请登录或提供有效 API Key' }).first()).toBeVisible()
  await expect(page.getByText('尚未创建管理员 Passkey')).toBeVisible()
  await expect(page.getByRole('heading', { name: '管理员设置' })).toBeVisible()
})

test('admin passkeys surface the live forbidden envelope', async ({ page }) => {
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/admin/passkeys', (route) => route.fulfill({
    status: 403,
    json: { error: { code: 'forbidden', message: 'API Key 权限不足' } },
  }))

  await page.goto('/')
  await page.getByRole('button', { name: '管理员' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: 'API Key 权限不足' }).first()).toBeVisible()
  await expect(page.getByText('尚未创建管理员 Passkey')).toBeVisible()
  await expect(page.getByRole('heading', { name: '管理员设置' })).toBeVisible()
})

test('admin passkeys surface the live not_found envelope', async ({ page }) => {
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/admin/passkeys', (route) => route.fulfill({
    status: 404,
    json: { error: { code: 'not_found', message: '接口不存在' } },
  }))

  await page.goto('/')
  await page.getByRole('button', { name: '管理员' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '接口不存在' }).first()).toBeVisible()
  await expect(page.getByText('尚未创建管理员 Passkey')).toBeVisible()
  await expect(page.getByRole('heading', { name: '管理员设置' })).toBeVisible()
})

test('admin passkeys surface the live internal_error envelope', async ({ page }) => {
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/admin/passkeys', (route) => route.fulfill({
    status: 500,
    json: { error: { code: 'internal_error', message: '服务暂时不可用' } },
  }))

  await page.goto('/')
  await page.getByRole('button', { name: '管理员' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '服务暂时不可用' }).first()).toBeVisible()
  await expect(page.getByText('尚未创建管理员 Passkey')).toBeVisible()
  await expect(page.getByRole('heading', { name: '管理员设置' })).toBeVisible()
})

test('admin passkey delete surfaces the live unauthorized envelope', async ({ page }) => {
  const existing = { id: 9, name: '办公室电脑', created_at: new Date().toISOString() }
  let deleteCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/admin/passkeys', (route) => route.fulfill({ json: { passkeys: [existing] } }))
  await page.route('**/api/v1/admin/passkeys/**', (route) => {
    deleteCalls += 1
    expect(route.request().method()).toBe('DELETE')
    return route.fulfill({
      status: 401,
      json: { error: { code: 'unauthorized', message: '请登录或提供有效 API Key' } },
    })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '管理员' }).click()
  await page.getByRole('button', { name: '删除 Passkey' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '请登录或提供有效 API Key' }).first()).toBeVisible()
  await expect(page.locator('.passkey-row')).toContainText('办公室电脑')
  expect(deleteCalls).toBe(1)
})

test('admin passkey delete surfaces the live forbidden envelope', async ({ page }) => {
  const existing = { id: 10, name: '办公室电脑', created_at: new Date().toISOString() }
  let deleteCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/admin/passkeys', (route) => route.fulfill({ json: { passkeys: [existing] } }))
  await page.route('**/api/v1/admin/passkeys/**', (route) => {
    deleteCalls += 1
    expect(route.request().method()).toBe('DELETE')
    return route.fulfill({
      status: 403,
      json: { error: { code: 'forbidden', message: 'API Key 权限不足' } },
    })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '管理员' }).click()
  await page.getByRole('button', { name: '删除 Passkey' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: 'API Key 权限不足' }).first()).toBeVisible()
  await expect(page.locator('.passkey-row')).toContainText('办公室电脑')
  expect(deleteCalls).toBe(1)
})

test('admin passkey delete surfaces the live not_found envelope', async ({ page }) => {
  const existing = { id: 11, name: '办公室电脑', created_at: new Date().toISOString() }
  let deleteCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/admin/passkeys', (route) => route.fulfill({ json: { passkeys: [existing] } }))
  await page.route('**/api/v1/admin/passkeys/**', (route) => {
    deleteCalls += 1
    expect(route.request().method()).toBe('DELETE')
    return route.fulfill({
      status: 404,
      json: { error: { code: 'not_found', message: '接口不存在' } },
    })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '管理员' }).click()
  await page.getByRole('button', { name: '删除 Passkey' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '接口不存在' }).first()).toBeVisible()
  await expect(page.locator('.passkey-row')).toContainText('办公室电脑')
  expect(deleteCalls).toBe(1)
})

test('admin passkey delete surfaces the live internal_error envelope', async ({ page }) => {
  const existing = { id: 12, name: '办公室电脑', created_at: new Date().toISOString() }
  let deleteCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/admin/passkeys', (route) => route.fulfill({ json: { passkeys: [existing] } }))
  await page.route('**/api/v1/admin/passkeys/**', (route) => {
    deleteCalls += 1
    expect(route.request().method()).toBe('DELETE')
    return route.fulfill({
      status: 500,
      json: { error: { code: 'internal_error', message: '服务暂时不可用' } },
    })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '管理员' }).click()
  await page.getByRole('button', { name: '删除 Passkey' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '服务暂时不可用' }).first()).toBeVisible()
  await expect(page.locator('.passkey-row')).toContainText('办公室电脑')
  expect(deleteCalls).toBe(1)
})

test('settings API key revoke surfaces the live unauthorized envelope', async ({ page }) => {
  const existing = {
    id: 13,
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
      status: 401,
      json: { error: { code: 'unauthorized', message: '请登录或提供有效 API Key' } },
    })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: 'API Key' }).click()
  await page.getByRole('button', { name: '撤销' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '请登录或提供有效 API Key' }).first()).toBeVisible()
  await expect(page.locator('.key-row')).toContainText('桌面小组件')
  expect(revokeCalls).toBe(1)
})

test('settings API key revoke surfaces the live forbidden envelope', async ({ page }) => {
  const existing = {
    id: 14,
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
      status: 403,
      json: { error: { code: 'forbidden', message: 'API Key 权限不足' } },
    })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: 'API Key' }).click()
  await page.getByRole('button', { name: '撤销' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: 'API Key 权限不足' }).first()).toBeVisible()
  await expect(page.locator('.key-row')).toContainText('桌面小组件')
  expect(revokeCalls).toBe(1)
})

test('settings API key revoke surfaces the live not_found envelope', async ({ page }) => {
  const existing = {
    id: 15,
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
      status: 404,
      json: { error: { code: 'not_found', message: '接口不存在' } },
    })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: 'API Key' }).click()
  await page.getByRole('button', { name: '撤销' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '接口不存在' }).first()).toBeVisible()
  await expect(page.locator('.key-row')).toContainText('桌面小组件')
  expect(revokeCalls).toBe(1)
})

test('settings API key revoke surfaces the live internal_error envelope', async ({ page }) => {
  const existing = {
    id: 16,
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
      json: { error: { code: 'internal_error', message: '服务暂时不可用' } },
    })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: 'API Key' }).click()
  await page.getByRole('button', { name: '撤销' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '服务暂时不可用' }).first()).toBeVisible()
  await expect(page.locator('.key-row')).toContainText('桌面小组件')
  expect(revokeCalls).toBe(1)
})

test('log clear surfaces the live unauthorized envelope', async ({ page }) => {
  let clearCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/logs**', (route) => {
    if (route.request().method() === 'DELETE') {
      clearCalls += 1
      return route.fulfill({
        status: 401,
        json: { error: { code: 'unauthorized', message: '请登录或提供有效 API Key' } },
      })
    }
    return route.fulfill({ json: { logs: [{ id: 1, type: 'audit', message: '保留日志', created_at: new Date().toISOString() }] } })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '日志' }).click()
  await expect(page.getByText('保留日志')).toBeVisible()
  await page.getByRole('button', { name: '清空' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '请登录或提供有效 API Key' }).first()).toBeVisible()
  await expect(page.getByText('保留日志')).toBeVisible()
  expect(clearCalls).toBe(1)
})

test('log clear surfaces the live internal_error envelope', async ({ page }) => {
  let clearCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/logs**', (route) => {
    if (route.request().method() === 'DELETE') {
      clearCalls += 1
      return route.fulfill({
        status: 500,
        json: { error: { code: 'internal_error', message: '服务暂时不可用' } },
      })
    }
    return route.fulfill({ json: { logs: [{ id: 1, type: 'audit', message: '保留日志', created_at: new Date().toISOString() }] } })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '日志' }).click()
  await expect(page.getByText('保留日志')).toBeVisible()
  await page.getByRole('button', { name: '清空' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '服务暂时不可用' }).first()).toBeVisible()
  await expect(page.getByText('保留日志')).toBeVisible()
  expect(clearCalls).toBe(1)
})

test('admin password update surfaces the live unauthorized envelope', async ({ page }) => {
  let updateCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/admin/passkeys', (route) => route.fulfill({ json: { passkeys: [] } }))
  await page.route('**/api/v1/admin/password', (route) => {
    updateCalls += 1
    expect(route.request().method()).toBe('PUT')
    return route.fulfill({
      status: 401,
      json: { error: { code: 'unauthorized', message: '请登录或提供有效 API Key' } },
    })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '管理员' }).click()
  await page.getByLabel('当前密码').fill(TEST_PASSWORD)
  await page.getByLabel('新密码', { exact: true }).fill('Rotated-Password-42!')
  await page.getByLabel('确认新密码').fill('Rotated-Password-42!')
  await page.getByRole('button', { name: '保存新密码' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '请登录或提供有效 API Key' }).first()).toBeVisible()
  await expect(page.getByRole('heading', { name: '管理员设置' })).toBeVisible()
  expect(updateCalls).toBe(1)
})

test('admin password update surfaces the live forbidden envelope', async ({ page }) => {
  let updateCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/admin/passkeys', (route) => route.fulfill({ json: { passkeys: [] } }))
  await page.route('**/api/v1/admin/password', (route) => {
    updateCalls += 1
    expect(route.request().method()).toBe('PUT')
    return route.fulfill({
      status: 403,
      json: { error: { code: 'forbidden', message: 'API Key 权限不足' } },
    })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '管理员' }).click()
  await page.getByLabel('当前密码').fill(TEST_PASSWORD)
  await page.getByLabel('新密码', { exact: true }).fill('Rotated-Password-42!')
  await page.getByLabel('确认新密码').fill('Rotated-Password-42!')
  await page.getByRole('button', { name: '保存新密码' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: 'API Key 权限不足' }).first()).toBeVisible()
  await expect(page.getByRole('heading', { name: '管理员设置' })).toBeVisible()
  expect(updateCalls).toBe(1)
})

test('admin password update surfaces the live not_found envelope', async ({ page }) => {
  let updateCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/admin/passkeys', (route) => route.fulfill({ json: { passkeys: [] } }))
  await page.route('**/api/v1/admin/password', (route) => {
    updateCalls += 1
    expect(route.request().method()).toBe('PUT')
    return route.fulfill({
      status: 404,
      json: { error: { code: 'not_found', message: '接口不存在' } },
    })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '管理员' }).click()
  await page.getByLabel('当前密码').fill(TEST_PASSWORD)
  await page.getByLabel('新密码', { exact: true }).fill('Rotated-Password-42!')
  await page.getByLabel('确认新密码').fill('Rotated-Password-42!')
  await page.getByRole('button', { name: '保存新密码' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '接口不存在' }).first()).toBeVisible()
  await expect(page.getByRole('heading', { name: '管理员设置' })).toBeVisible()
  expect(updateCalls).toBe(1)
})

test('admin password update surfaces the live internal_error envelope', async ({ page }) => {
  let updateCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/admin/passkeys', (route) => route.fulfill({ json: { passkeys: [] } }))
  await page.route('**/api/v1/admin/password', (route) => {
    updateCalls += 1
    expect(route.request().method()).toBe('PUT')
    return route.fulfill({
      status: 500,
      json: { error: { code: 'internal_error', message: '服务暂时不可用' } },
    })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '管理员' }).click()
  await page.getByLabel('当前密码').fill(TEST_PASSWORD)
  await page.getByLabel('新密码', { exact: true }).fill('Rotated-Password-42!')
  await page.getByLabel('确认新密码').fill('Rotated-Password-42!')
  await page.getByRole('button', { name: '保存新密码' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '服务暂时不可用' }).first()).toBeVisible()
  await expect(page.getByRole('heading', { name: '管理员设置' })).toBeVisible()
  expect(updateCalls).toBe(1)
})

test('settings API key create surfaces the live unauthorized envelope', async ({ page }) => {
  let createCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/api-keys', (route) => {
    if (route.request().method() === 'POST') {
      createCalls += 1
      return route.fulfill({
        status: 401,
        json: { error: { code: 'unauthorized', message: '请登录或提供有效 API Key' } },
      })
    }
    return route.fulfill({ json: { keys: [] } })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: 'API Key' }).click()
  await page.getByRole('button', { name: '创建 Key' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '请登录或提供有效 API Key' }).first()).toBeVisible()
  await expect(page.getByText('仅显示一次')).toHaveCount(0)
  expect(createCalls).toBe(1)
})

test('settings API key create surfaces the live forbidden envelope', async ({ page }) => {
  let createCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/api-keys', (route) => {
    if (route.request().method() === 'POST') {
      createCalls += 1
      return route.fulfill({
        status: 403,
        json: { error: { code: 'forbidden', message: 'API Key 权限不足' } },
      })
    }
    return route.fulfill({ json: { keys: [] } })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: 'API Key' }).click()
  await page.getByRole('button', { name: '创建 Key' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: 'API Key 权限不足' }).first()).toBeVisible()
  await expect(page.getByText('仅显示一次')).toHaveCount(0)
  expect(createCalls).toBe(1)
})

test('settings API key create surfaces the live not_found envelope', async ({ page }) => {
  let createCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/api-keys', (route) => {
    if (route.request().method() === 'POST') {
      createCalls += 1
      return route.fulfill({
        status: 404,
        json: { error: { code: 'not_found', message: '接口不存在' } },
      })
    }
    return route.fulfill({ json: { keys: [] } })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: 'API Key' }).click()
  await page.getByRole('button', { name: '创建 Key' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '接口不存在' }).first()).toBeVisible()
  await expect(page.getByText('仅显示一次')).toHaveCount(0)
  expect(createCalls).toBe(1)
})

test('settings API key create surfaces the live internal_error envelope', async ({ page }) => {
  let createCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/api-keys', (route) => {
    if (route.request().method() === 'POST') {
      createCalls += 1
      return route.fulfill({
        status: 500,
        json: { error: { code: 'internal_error', message: '服务暂时不可用' } },
      })
    }
    return route.fulfill({ json: { keys: [] } })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: 'API Key' }).click()
  await page.getByRole('button', { name: '创建 Key' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '服务暂时不可用' }).first()).toBeVisible()
  await expect(page.getByText('仅显示一次')).toHaveCount(0)
  expect(createCalls).toBe(1)
})

test('settings save surfaces the live unauthorized envelope', async ({ page }) => {
  let saveCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/config', (route) => {
    if (route.request().method() === 'PUT') {
      saveCalls += 1
      return route.fulfill({
        status: 401,
        json: { error: { code: 'unauthorized', message: '请登录或提供有效 API Key' } },
      })
    }
    return route.fulfill({ json: dashboardConfig })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '请登录或提供有效 API Key' }).first()).toBeVisible()
  expect(saveCalls).toBe(1)
})

test('settings save surfaces the live internal_error envelope', async ({ page }) => {
  let saveCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/config', (route) => {
    if (route.request().method() === 'PUT') {
      saveCalls += 1
      return route.fulfill({
        status: 500,
        json: { error: { code: 'internal_error', message: '服务暂时不可用' } },
      })
    }
    return route.fulfill({ json: dashboardConfig })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '服务暂时不可用' }).first()).toBeVisible()
  expect(saveCalls).toBe(1)
})

test('instance start surfaces the live unauthorized envelope', async ({ page }) => {
  let startCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page, {
    ...dashboardStatus,
    accounts: [{ ...dashboardAccount, instance_status: 'Stopped' }],
  })
  await page.route('**/api/v1/accounts/1/actions/start', (route) => {
    startCalls += 1
    expect(route.request().method()).toBe('POST')
    return route.fulfill({
      status: 401,
      json: { error: { code: 'unauthorized', message: '请登录或提供有效 API Key' } },
    })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '开机' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '请登录或提供有效 API Key' }).first()).toBeVisible()
  expect(startCalls).toBe(1)
})

test('instance stop surfaces the live unauthorized envelope', async ({ page }) => {
  let stopCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/accounts/1/actions/stop', (route) => {
    stopCalls += 1
    expect(route.request().method()).toBe('POST')
    return route.fulfill({
      status: 401,
      json: { error: { code: 'unauthorized', message: '请登录或提供有效 API Key' } },
    })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '关机' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '请登录或提供有效 API Key' }).first()).toBeVisible()
  expect(stopCalls).toBe(1)
})

test('instance start surfaces the live internal_error envelope', async ({ page }) => {
  let startCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page, {
    ...dashboardStatus,
    accounts: [{ ...dashboardAccount, instance_status: 'Stopped' }],
  })
  await page.route('**/api/v1/accounts/1/actions/start', (route) => {
    startCalls += 1
    expect(route.request().method()).toBe('POST')
    return route.fulfill({
      status: 500,
      json: { error: { code: 'internal_error', message: '服务暂时不可用' } },
    })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '开机' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '服务暂时不可用' }).first()).toBeVisible()
  expect(startCalls).toBe(1)
})

test('instance stop surfaces the live internal_error envelope', async ({ page }) => {
  let stopCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/accounts/1/actions/stop', (route) => {
    stopCalls += 1
    expect(route.request().method()).toBe('POST')
    return route.fulfill({
      status: 500,
      json: { error: { code: 'internal_error', message: '服务暂时不可用' } },
    })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '关机' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '服务暂时不可用' }).first()).toBeVisible()
  expect(stopCalls).toBe(1)
})

test('instance refresh surfaces the live unauthorized envelope', async ({ page }) => {
  let refreshCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/accounts/1/refresh', (route) => {
    refreshCalls += 1
    expect(route.request().method()).toBe('POST')
    return route.fulfill({
      status: 401,
      json: { error: { code: 'unauthorized', message: '请登录或提供有效 API Key' } },
    })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '刷新实例' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '请登录或提供有效 API Key' }).first()).toBeVisible()
  expect(refreshCalls).toBe(1)
})

test('instance refresh surfaces the live forbidden envelope', async ({ page }) => {
  let refreshCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/accounts/1/refresh', (route) => {
    refreshCalls += 1
    expect(route.request().method()).toBe('POST')
    return route.fulfill({
      status: 403,
      json: { error: { code: 'forbidden', message: 'API Key 权限不足' } },
    })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '刷新实例' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: 'API Key 权限不足' }).first()).toBeVisible()
  expect(refreshCalls).toBe(1)
})

test('instance refresh surfaces the live not_found envelope', async ({ page }) => {
  let refreshCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/accounts/1/refresh', (route) => {
    refreshCalls += 1
    expect(route.request().method()).toBe('POST')
    return route.fulfill({
      status: 404,
      json: { error: { code: 'not_found', message: '接口不存在' } },
    })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '刷新实例' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '接口不存在' }).first()).toBeVisible()
  expect(refreshCalls).toBe(1)
})

test('instance refresh surfaces the live internal_error envelope', async ({ page }) => {
  let refreshCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/accounts/1/refresh', (route) => {
    refreshCalls += 1
    expect(route.request().method()).toBe('POST')
    return route.fulfill({
      status: 500,
      json: { error: { code: 'internal_error', message: '服务暂时不可用' } },
    })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '刷新实例' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '服务暂时不可用' }).first()).toBeVisible()
  expect(refreshCalls).toBe(1)
})

test('refresh-all surfaces the live unauthorized envelope', async ({ page }) => {
  let refreshCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/accounts/refresh', (route) => {
    refreshCalls += 1
    expect(route.request().method()).toBe('POST')
    return route.fulfill({
      status: 401,
      json: { error: { code: 'unauthorized', message: '请登录或提供有效 API Key' } },
    })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '强制刷新全部实例' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '请登录或提供有效 API Key' }).first()).toBeVisible()
  expect(refreshCalls).toBe(1)
})

test('refresh-all surfaces the live forbidden envelope', async ({ page }) => {
  let refreshCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/accounts/refresh', (route) => {
    refreshCalls += 1
    expect(route.request().method()).toBe('POST')
    return route.fulfill({
      status: 403,
      json: { error: { code: 'forbidden', message: 'API Key 权限不足' } },
    })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '强制刷新全部实例' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: 'API Key 权限不足' }).first()).toBeVisible()
  expect(refreshCalls).toBe(1)
})

test('refresh-all surfaces the live not_found envelope', async ({ page }) => {
  let refreshCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/accounts/refresh', (route) => {
    refreshCalls += 1
    expect(route.request().method()).toBe('POST')
    return route.fulfill({
      status: 404,
      json: { error: { code: 'not_found', message: '接口不存在' } },
    })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '强制刷新全部实例' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '接口不存在' }).first()).toBeVisible()
  expect(refreshCalls).toBe(1)
})

test('refresh-all surfaces the live internal_error envelope', async ({ page }) => {
  let refreshCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/accounts/refresh', (route) => {
    refreshCalls += 1
    expect(route.request().method()).toBe('POST')
    return route.fulfill({
      status: 500,
      json: { error: { code: 'internal_error', message: '服务暂时不可用' } },
    })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '强制刷新全部实例' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '服务暂时不可用' }).first()).toBeVisible()
  expect(refreshCalls).toBe(1)
})

test('settings email test surfaces the live unauthorized envelope', async ({ page }) => {
  let testCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/notifications/test/email', (route) => {
    testCalls += 1
    expect(route.request().method()).toBe('POST')
    return route.fulfill({
      status: 401,
      json: { error: { code: 'unauthorized', message: '请登录或提供有效 API Key' } },
    })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: '发送测试' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '请登录或提供有效 API Key' }).first()).toBeVisible()
  expect(testCalls).toBe(1)
})

test('settings email test surfaces the live forbidden envelope', async ({ page }) => {
  let testCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/notifications/test/email', (route) => {
    testCalls += 1
    expect(route.request().method()).toBe('POST')
    return route.fulfill({
      status: 403,
      json: { error: { code: 'forbidden', message: 'API Key 权限不足' } },
    })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: '发送测试' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: 'API Key 权限不足' }).first()).toBeVisible()
  expect(testCalls).toBe(1)
})

test('settings email test surfaces the live not_found envelope', async ({ page }) => {
  let testCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/notifications/test/email', (route) => {
    testCalls += 1
    expect(route.request().method()).toBe('POST')
    return route.fulfill({
      status: 404,
      json: { error: { code: 'not_found', message: '接口不存在' } },
    })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: '发送测试' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '接口不存在' }).first()).toBeVisible()
  expect(testCalls).toBe(1)
})

test('settings email test surfaces the live internal_error envelope', async ({ page }) => {
  let testCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/notifications/test/email', (route) => {
    testCalls += 1
    expect(route.request().method()).toBe('POST')
    return route.fulfill({
      status: 500,
      json: { error: { code: 'internal_error', message: '服务暂时不可用' } },
    })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: '发送测试' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '服务暂时不可用' }).first()).toBeVisible()
  expect(testCalls).toBe(1)
})

test('settings telegram test surfaces the live unauthorized envelope', async ({ page }) => {
  let testCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/notifications/test/telegram', (route) => {
    testCalls += 1
    expect(route.request().method()).toBe('POST')
    return route.fulfill({
      status: 401,
      json: { error: { code: 'unauthorized', message: '请登录或提供有效 API Key' } },
    })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: 'Telegram' }).click()
  await page.getByRole('button', { name: '发送测试' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '请登录或提供有效 API Key' }).first()).toBeVisible()
  expect(testCalls).toBe(1)
})

test('settings telegram test surfaces the live forbidden envelope', async ({ page }) => {
  let testCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/notifications/test/telegram', (route) => {
    testCalls += 1
    expect(route.request().method()).toBe('POST')
    return route.fulfill({
      status: 403,
      json: { error: { code: 'forbidden', message: 'API Key 权限不足' } },
    })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: 'Telegram' }).click()
  await page.getByRole('button', { name: '发送测试' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: 'API Key 权限不足' }).first()).toBeVisible()
  expect(testCalls).toBe(1)
})

test('settings telegram test surfaces the live not_found envelope', async ({ page }) => {
  let testCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/notifications/test/telegram', (route) => {
    testCalls += 1
    expect(route.request().method()).toBe('POST')
    return route.fulfill({
      status: 404,
      json: { error: { code: 'not_found', message: '接口不存在' } },
    })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: 'Telegram' }).click()
  await page.getByRole('button', { name: '发送测试' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '接口不存在' }).first()).toBeVisible()
  expect(testCalls).toBe(1)
})

test('settings telegram test surfaces the live internal_error envelope', async ({ page }) => {
  let testCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/notifications/test/telegram', (route) => {
    testCalls += 1
    expect(route.request().method()).toBe('POST')
    return route.fulfill({
      status: 500,
      json: { error: { code: 'internal_error', message: '服务暂时不可用' } },
    })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: 'Telegram' }).click()
  await page.getByRole('button', { name: '发送测试' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '服务暂时不可用' }).first()).toBeVisible()
  expect(testCalls).toBe(1)
})

test('settings webhook test surfaces the live unauthorized envelope', async ({ page }) => {
  let testCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/notifications/test/webhook', (route) => {
    testCalls += 1
    expect(route.request().method()).toBe('POST')
    return route.fulfill({
      status: 401,
      json: { error: { code: 'unauthorized', message: '请登录或提供有效 API Key' } },
    })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: 'Webhook' }).click()
  await page.getByRole('button', { name: '发送测试' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '请登录或提供有效 API Key' }).first()).toBeVisible()
  expect(testCalls).toBe(1)
})

test('settings webhook test surfaces the live forbidden envelope', async ({ page }) => {
  let testCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/notifications/test/webhook', (route) => {
    testCalls += 1
    expect(route.request().method()).toBe('POST')
    return route.fulfill({
      status: 403,
      json: { error: { code: 'forbidden', message: 'API Key 权限不足' } },
    })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: 'Webhook' }).click()
  await page.getByRole('button', { name: '发送测试' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: 'API Key 权限不足' }).first()).toBeVisible()
  expect(testCalls).toBe(1)
})

test('settings webhook test surfaces the live not_found envelope', async ({ page }) => {
  let testCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/notifications/test/webhook', (route) => {
    testCalls += 1
    expect(route.request().method()).toBe('POST')
    return route.fulfill({
      status: 404,
      json: { error: { code: 'not_found', message: '接口不存在' } },
    })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: 'Webhook' }).click()
  await page.getByRole('button', { name: '发送测试' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '接口不存在' }).first()).toBeVisible()
  expect(testCalls).toBe(1)
})

test('settings webhook test surfaces the live internal_error envelope', async ({ page }) => {
  let testCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/notifications/test/webhook', (route) => {
    testCalls += 1
    expect(route.request().method()).toBe('POST')
    return route.fulfill({
      status: 500,
      json: { error: { code: 'internal_error', message: '服务暂时不可用' } },
    })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: 'Webhook' }).click()
  await page.getByRole('button', { name: '发送测试' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '服务暂时不可用' }).first()).toBeVisible()
  expect(testCalls).toBe(1)
})

test('logout surfaces the live unauthorized envelope', async ({ page }) => {
  let logoutCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/auth/logout', (route) => {
    logoutCalls += 1
    expect(route.request().method()).toBe('POST')
    return route.fulfill({
      status: 401,
      json: { error: { code: 'unauthorized', message: '请登录或提供有效 API Key' } },
    })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '退出' }).click()
  await expect(page.getByRole('heading', { name: '欢迎回来' })).toBeVisible()
  expect(logoutCalls).toBe(1)
})

test('logout surfaces the live forbidden envelope', async ({ page }) => {
  let logoutCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/auth/logout', (route) => {
    logoutCalls += 1
    expect(route.request().method()).toBe('POST')
    return route.fulfill({
      status: 403,
      json: { error: { code: 'forbidden', message: 'API Key 权限不足' } },
    })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '退出' }).click()
  await expect(page.getByRole('heading', { name: '欢迎回来' })).toBeVisible()
  expect(logoutCalls).toBe(1)
})

test('logout surfaces the live not_found envelope', async ({ page }) => {
  let logoutCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/auth/logout', (route) => {
    logoutCalls += 1
    expect(route.request().method()).toBe('POST')
    return route.fulfill({
      status: 404,
      json: { error: { code: 'not_found', message: '接口不存在' } },
    })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '退出' }).click()
  await expect(page.getByRole('heading', { name: '欢迎回来' })).toBeVisible()
  expect(logoutCalls).toBe(1)
})

test('logout surfaces the live internal_error envelope', async ({ page }) => {
  let logoutCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/auth/logout', (route) => {
    logoutCalls += 1
    expect(route.request().method()).toBe('POST')
    return route.fulfill({
      status: 500,
      json: { error: { code: 'internal_error', message: '服务暂时不可用' } },
    })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '退出' }).click()
  await expect(page.getByRole('heading', { name: '欢迎回来' })).toBeVisible()
  expect(logoutCalls).toBe(1)
})

test('instance refresh surfaces the live job unauthorized envelope', async ({ page }) => {
  let refreshCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/accounts/1/refresh', (route) => {
    refreshCalls += 1
    expect(route.request().method()).toBe('POST')
    return route.fulfill({ status: 202, json: jobFixture('refresh-unauth', 'queued', 1) })
  })
  await page.route('**/api/v1/jobs/**', (route) => route.fulfill({
    status: 401,
    json: { error: { code: 'unauthorized', message: '请登录或提供有效 API Key' } },
  }))

  await page.goto('/')
  await page.getByRole('button', { name: '刷新实例' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '请登录或提供有效 API Key' }).first()).toBeVisible()
  expect(refreshCalls).toBe(1)
})

test('instance refresh surfaces the live job forbidden envelope', async ({ page }) => {
  let refreshCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/accounts/1/refresh', (route) => {
    refreshCalls += 1
    expect(route.request().method()).toBe('POST')
    return route.fulfill({ status: 202, json: jobFixture('refresh-forbidden', 'queued', 1) })
  })
  await page.route('**/api/v1/jobs/**', (route) => route.fulfill({
    status: 403,
    json: { error: { code: 'forbidden', message: 'API Key 权限不足' } },
  }))

  await page.goto('/')
  await page.getByRole('button', { name: '刷新实例' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: 'API Key 权限不足' }).first()).toBeVisible()
  expect(refreshCalls).toBe(1)
})

test('instance refresh surfaces the live job not_found envelope', async ({ page }) => {
  let refreshCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/accounts/1/refresh', (route) => {
    refreshCalls += 1
    expect(route.request().method()).toBe('POST')
    return route.fulfill({ status: 202, json: jobFixture('refresh-not-found', 'queued', 1) })
  })
  await page.route('**/api/v1/jobs/**', (route) => route.fulfill({
    status: 404,
    json: { error: { code: 'not_found', message: '接口不存在' } },
  }))

  await page.goto('/')
  await page.getByRole('button', { name: '刷新实例' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '接口不存在' }).first()).toBeVisible()
  expect(refreshCalls).toBe(1)
})

test('instance refresh surfaces the live job internal_error envelope', async ({ page }) => {
  let refreshCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/accounts/1/refresh', (route) => {
    refreshCalls += 1
    expect(route.request().method()).toBe('POST')
    return route.fulfill({ status: 202, json: jobFixture('refresh-internal', 'queued', 1) })
  })
  await page.route('**/api/v1/jobs/**', (route) => route.fulfill({
    status: 500,
    json: { error: { code: 'internal_error', message: '服务暂时不可用' } },
  }))

  await page.goto('/')
  await page.getByRole('button', { name: '刷新实例' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '服务暂时不可用' }).first()).toBeVisible()
  expect(refreshCalls).toBe(1)
})

test('dashboard status poll surfaces the live unauthorized envelope', async ({ page }) => {
  await page.clock.install()
  let failPoll = false
  let pollCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/status', (route) => {
    if (!failPoll) return route.fulfill({ json: dashboardStatus })
    pollCalls += 1
    return route.fulfill({
      status: 401,
      json: { error: { code: 'unauthorized', message: '请登录或提供有效 API Key' } },
    })
  })

  await page.goto('/')
  await expect(page.getByRole('heading', { name: '资源控制台' })).toBeVisible()
  failPoll = true
  await page.clock.fastForward(31_000)
  await expect(page.getByRole('heading', { name: '欢迎回来' })).toBeVisible()
  expect(pollCalls).toBeGreaterThan(0)
})

test('dashboard status poll keeps the console on the live forbidden envelope', async ({ page }) => {
  await page.clock.install()
  let failPoll = false
  let pollCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/status', (route) => {
    if (!failPoll) return route.fulfill({ json: dashboardStatus })
    pollCalls += 1
    return route.fulfill({
      status: 403,
      json: { error: { code: 'forbidden', message: 'API Key 权限不足' } },
    })
  })

  await page.goto('/')
  await expect(page.getByRole('heading', { name: '资源控制台' })).toBeVisible()
  failPoll = true
  await page.clock.fastForward(31_000)
  await expect(page.getByRole('heading', { name: '资源控制台' })).toBeVisible()
  await expect(page.locator('.toast--error')).toHaveCount(0)
  expect(pollCalls).toBeGreaterThan(0)
})

test('dashboard status poll keeps the console on the live not_found envelope', async ({ page }) => {
  await page.clock.install()
  let failPoll = false
  let pollCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/status', (route) => {
    if (!failPoll) return route.fulfill({ json: dashboardStatus })
    pollCalls += 1
    return route.fulfill({
      status: 404,
      json: { error: { code: 'not_found', message: '接口不存在' } },
    })
  })

  await page.goto('/')
  await expect(page.getByRole('heading', { name: '资源控制台' })).toBeVisible()
  failPoll = true
  await page.clock.fastForward(31_000)
  await expect(page.getByRole('heading', { name: '资源控制台' })).toBeVisible()
  await expect(page.locator('.toast--error')).toHaveCount(0)
  expect(pollCalls).toBeGreaterThan(0)
})

test('dashboard status poll keeps the console on the live internal_error envelope', async ({ page }) => {
  await page.clock.install()
  let failPoll = false
  let pollCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/status', (route) => {
    if (!failPoll) return route.fulfill({ json: dashboardStatus })
    pollCalls += 1
    return route.fulfill({
      status: 500,
      json: { error: { code: 'internal_error', message: '服务暂时不可用' } },
    })
  })

  await page.goto('/')
  await expect(page.getByRole('heading', { name: '资源控制台' })).toBeVisible()
  failPoll = true
  await page.clock.fastForward(31_000)
  await expect(page.getByRole('heading', { name: '资源控制台' })).toBeVisible()
  await expect(page.locator('.toast--error')).toHaveCount(0)
  expect(pollCalls).toBeGreaterThan(0)
})

test('login surfaces the live config unauthorized envelope when dashboard load fails', async ({ page }) => {
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
    return route.fulfill({
      status: 401,
      json: { error: { code: 'unauthorized', message: '请登录或提供有效 API Key' } },
    })
  })

  await page.goto('/')
  await page.getByLabel('管理员密码').fill(TEST_PASSWORD)
  await page.getByRole('button', { name: '安全登录' }).click()
  await expect(page.locator('.inline-error')).toContainText('请登录或提供有效 API Key')
  await expect(page.getByRole('heading', { name: '欢迎回来' })).toBeVisible()
})

test('login surfaces the live config forbidden envelope when dashboard load fails', async ({ page }) => {
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
    return route.fulfill({
      status: 403,
      json: { error: { code: 'forbidden', message: 'API Key 权限不足' } },
    })
  })

  await page.goto('/')
  await page.getByLabel('管理员密码').fill(TEST_PASSWORD)
  await page.getByRole('button', { name: '安全登录' }).click()
  await expect(page.locator('.inline-error')).toContainText('API Key 权限不足')
  await expect(page.getByRole('heading', { name: '欢迎回来' })).toBeVisible()
})

test('login surfaces the live config not_found envelope when dashboard load fails', async ({ page }) => {
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
    return route.fulfill({
      status: 404,
      json: { error: { code: 'not_found', message: '接口不存在' } },
    })
  })

  await page.goto('/')
  await page.getByLabel('管理员密码').fill(TEST_PASSWORD)
  await page.getByRole('button', { name: '安全登录' }).click()
  await expect(page.locator('.inline-error')).toContainText('接口不存在')
  await expect(page.getByRole('heading', { name: '欢迎回来' })).toBeVisible()
})

test('login surfaces the live config internal_error envelope when dashboard load fails', async ({ page }) => {
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
    return route.fulfill({
      status: 500,
      json: { error: { code: 'internal_error', message: '服务暂时不可用' } },
    })
  })

  await page.goto('/')
  await page.getByLabel('管理员密码').fill(TEST_PASSWORD)
  await page.getByRole('button', { name: '安全登录' }).click()
  await expect(page.locator('.inline-error')).toContainText('服务暂时不可用')
  await expect(page.getByRole('heading', { name: '欢迎回来' })).toBeVisible()
})

test('login surfaces the live status unauthorized envelope when dashboard load fails', async ({ page }) => {
  await mockInitStatus(page, true)
  let authed = false
  await page.route('**/api/v1/auth/login', async (route) => {
    authed = true
    await route.fulfill({ json: { success: true, csrf_token: 'test-csrf' } })
  })
  await page.route('**/api/v1/status', (route) => {
    if (!authed) return route.fulfill({ status: 401, json: { error: { code: 'unauthorized', message: '请登录或提供有效 API Key' } } })
    return route.fulfill({
      status: 401,
      json: { error: { code: 'unauthorized', message: '请登录或提供有效 API Key' } },
    })
  })
  await page.route('**/api/v1/config', (route) => {
    if (!authed) return route.fulfill({ status: 401, json: { error: { code: 'unauthorized', message: '请登录或提供有效 API Key' } } })
    return route.fulfill({ json: dashboardConfig })
  })

  await page.goto('/')
  await page.getByLabel('管理员密码').fill(TEST_PASSWORD)
  await page.getByRole('button', { name: '安全登录' }).click()
  await expect(page.locator('.inline-error')).toContainText('请登录或提供有效 API Key')
  await expect(page.getByRole('heading', { name: '欢迎回来' })).toBeVisible()
})

test('login surfaces the live status forbidden envelope when dashboard load fails', async ({ page }) => {
  await mockInitStatus(page, true)
  let authed = false
  await page.route('**/api/v1/auth/login', async (route) => {
    authed = true
    await route.fulfill({ json: { success: true, csrf_token: 'test-csrf' } })
  })
  await page.route('**/api/v1/status', (route) => {
    if (!authed) return route.fulfill({ status: 401, json: { error: { code: 'unauthorized', message: '请登录或提供有效 API Key' } } })
    return route.fulfill({
      status: 403,
      json: { error: { code: 'forbidden', message: 'API Key 权限不足' } },
    })
  })
  await page.route('**/api/v1/config', (route) => {
    if (!authed) return route.fulfill({ status: 401, json: { error: { code: 'unauthorized', message: '请登录或提供有效 API Key' } } })
    return route.fulfill({ json: dashboardConfig })
  })

  await page.goto('/')
  await page.getByLabel('管理员密码').fill(TEST_PASSWORD)
  await page.getByRole('button', { name: '安全登录' }).click()
  await expect(page.locator('.inline-error')).toContainText('API Key 权限不足')
  await expect(page.getByRole('heading', { name: '欢迎回来' })).toBeVisible()
})

test('login surfaces the live status not_found envelope when dashboard load fails', async ({ page }) => {
  await mockInitStatus(page, true)
  let authed = false
  await page.route('**/api/v1/auth/login', async (route) => {
    authed = true
    await route.fulfill({ json: { success: true, csrf_token: 'test-csrf' } })
  })
  await page.route('**/api/v1/status', (route) => {
    if (!authed) return route.fulfill({ status: 401, json: { error: { code: 'unauthorized', message: '请登录或提供有效 API Key' } } })
    return route.fulfill({
      status: 404,
      json: { error: { code: 'not_found', message: '接口不存在' } },
    })
  })
  await page.route('**/api/v1/config', (route) => {
    if (!authed) return route.fulfill({ status: 401, json: { error: { code: 'unauthorized', message: '请登录或提供有效 API Key' } } })
    return route.fulfill({ json: dashboardConfig })
  })

  await page.goto('/')
  await page.getByLabel('管理员密码').fill(TEST_PASSWORD)
  await page.getByRole('button', { name: '安全登录' }).click()
  await expect(page.locator('.inline-error')).toContainText('接口不存在')
  await expect(page.getByRole('heading', { name: '欢迎回来' })).toBeVisible()
})

test('login surfaces the live status internal_error envelope when dashboard load fails', async ({ page }) => {
  await mockInitStatus(page, true)
  let authed = false
  await page.route('**/api/v1/auth/login', async (route) => {
    authed = true
    await route.fulfill({ json: { success: true, csrf_token: 'test-csrf' } })
  })
  await page.route('**/api/v1/status', (route) => {
    if (!authed) return route.fulfill({ status: 401, json: { error: { code: 'unauthorized', message: '请登录或提供有效 API Key' } } })
    return route.fulfill({
      status: 500,
      json: { error: { code: 'internal_error', message: '服务暂时不可用' } },
    })
  })
  await page.route('**/api/v1/config', (route) => {
    if (!authed) return route.fulfill({ status: 401, json: { error: { code: 'unauthorized', message: '请登录或提供有效 API Key' } } })
    return route.fulfill({ json: dashboardConfig })
  })

  await page.goto('/')
  await page.getByLabel('管理员密码').fill(TEST_PASSWORD)
  await page.getByRole('button', { name: '安全登录' }).click()
  await expect(page.locator('.inline-error')).toContainText('服务暂时不可用')
  await expect(page.getByRole('heading', { name: '欢迎回来' })).toBeVisible()
})

test('init-status failure surfaces the live unauthorized envelope', async ({ page }) => {
  await page.route('**/api/v1/system/init-status', (route) => route.fulfill({
    status: 401,
    json: { error: { code: 'unauthorized', message: '请登录或提供有效 API Key' } },
  }))

  await page.goto('/')
  await expect(page.getByRole('heading', { name: '控制台暂时不可用' })).toBeVisible()
  await expect(page.getByText('请登录或提供有效 API Key')).toBeVisible()
})

test('init-status failure surfaces the live forbidden envelope', async ({ page }) => {
  await page.route('**/api/v1/system/init-status', (route) => route.fulfill({
    status: 403,
    json: { error: { code: 'forbidden', message: 'API Key 权限不足' } },
  }))

  await page.goto('/')
  await expect(page.getByRole('heading', { name: '控制台暂时不可用' })).toBeVisible()
  await expect(page.getByText('API Key 权限不足')).toBeVisible()
})

test('init-status failure surfaces the live not_found envelope', async ({ page }) => {
  await page.route('**/api/v1/system/init-status', (route) => route.fulfill({
    status: 404,
    json: { error: { code: 'not_found', message: '接口不存在' } },
  }))

  await page.goto('/')
  await expect(page.getByRole('heading', { name: '控制台暂时不可用' })).toBeVisible()
  await expect(page.getByText('接口不存在')).toBeVisible()
})

test('init-status failure surfaces the live internal_error envelope', async ({ page }) => {
  await page.route('**/api/v1/system/init-status', (route) => route.fulfill({
    status: 500,
    json: { error: { code: 'internal_error', message: '服务暂时不可用' } },
  }))

  await page.goto('/')
  await expect(page.getByRole('heading', { name: '控制台暂时不可用' })).toBeVisible()
  await expect(page.getByText('服务暂时不可用')).toBeVisible()
})

test('wizard surfaces the live unauthorized envelope and stays on install', async ({ page }) => {
  await mockInitStatus(page, false)
  await page.route('**/api/v1/setup', (route) => route.fulfill({
    status: 401,
    json: { error: { code: 'unauthorized', message: '请登录或提供有效 API Key' } },
  }))

  await page.goto('/')
  const passwords = page.locator('input[type="password"]')
  await passwords.nth(0).fill(TEST_PASSWORD)
  await passwords.nth(1).fill(TEST_PASSWORD)
  await page.getByRole('button', { name: '继续' }).click()
  await page.getByRole('button', { name: '继续' }).click()
  await page.getByRole('button', { name: '完成安装' }).click()
  await expect(page.getByText('请登录或提供有效 API Key')).toBeVisible()
  await expect(page.getByRole('heading', { name: '连接云端实例' })).toBeVisible()
})

test('wizard surfaces the live forbidden envelope and stays on install', async ({ page }) => {
  await mockInitStatus(page, false)
  await page.route('**/api/v1/setup', (route) => route.fulfill({
    status: 403,
    json: { error: { code: 'forbidden', message: 'API Key 权限不足' } },
  }))

  await page.goto('/')
  const passwords = page.locator('input[type="password"]')
  await passwords.nth(0).fill(TEST_PASSWORD)
  await passwords.nth(1).fill(TEST_PASSWORD)
  await page.getByRole('button', { name: '继续' }).click()
  await page.getByRole('button', { name: '继续' }).click()
  await page.getByRole('button', { name: '完成安装' }).click()
  await expect(page.getByText('API Key 权限不足')).toBeVisible()
  await expect(page.getByRole('heading', { name: '连接云端实例' })).toBeVisible()
})

test('wizard surfaces the live not_found envelope and stays on install', async ({ page }) => {
  await mockInitStatus(page, false)
  await page.route('**/api/v1/setup', (route) => route.fulfill({
    status: 404,
    json: { error: { code: 'not_found', message: '接口不存在' } },
  }))

  await page.goto('/')
  const passwords = page.locator('input[type="password"]')
  await passwords.nth(0).fill(TEST_PASSWORD)
  await passwords.nth(1).fill(TEST_PASSWORD)
  await page.getByRole('button', { name: '继续' }).click()
  await page.getByRole('button', { name: '继续' }).click()
  await page.getByRole('button', { name: '完成安装' }).click()
  await expect(page.getByText('接口不存在')).toBeVisible()
  await expect(page.getByRole('heading', { name: '连接云端实例' })).toBeVisible()
})

test('wizard surfaces the live internal_error envelope and stays on install', async ({ page }) => {
  await mockInitStatus(page, false)
  await page.route('**/api/v1/setup', (route) => route.fulfill({
    status: 500,
    json: { error: { code: 'internal_error', message: '服务暂时不可用' } },
  }))

  await page.goto('/')
  const passwords = page.locator('input[type="password"]')
  await passwords.nth(0).fill(TEST_PASSWORD)
  await passwords.nth(1).fill(TEST_PASSWORD)
  await page.getByRole('button', { name: '继续' }).click()
  await page.getByRole('button', { name: '继续' }).click()
  await page.getByRole('button', { name: '完成安装' }).click()
  await expect(page.getByText('服务暂时不可用')).toBeVisible()
  await expect(page.getByRole('heading', { name: '连接云端实例' })).toBeVisible()
})

test('instance start surfaces the live invalid_id envelope', async ({ page }) => {
  let startCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page, {
    ...dashboardStatus,
    accounts: [{ ...dashboardAccount, instance_status: 'Stopped' }],
  })
  await page.route('**/api/v1/accounts/1/actions/start', (route) => {
    startCalls += 1
    expect(route.request().method()).toBe('POST')
    return route.fulfill({
      status: 400,
      json: { error: { code: 'invalid_id', message: '无效 ID' } },
    })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '开机' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '无效 ID' }).first()).toBeVisible()
  expect(startCalls).toBe(1)
})

test('instance stop surfaces the live invalid_id envelope', async ({ page }) => {
  let stopCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/accounts/1/actions/stop', (route) => {
    stopCalls += 1
    expect(route.request().method()).toBe('POST')
    return route.fulfill({
      status: 400,
      json: { error: { code: 'invalid_id', message: '无效 ID' } },
    })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '关机' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '无效 ID' }).first()).toBeVisible()
  expect(stopCalls).toBe(1)
})

test('instance start surfaces the live job_not_found envelope', async ({ page }) => {
  let startCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page, {
    ...dashboardStatus,
    accounts: [{ ...dashboardAccount, instance_status: 'Stopped' }],
  })
  await page.route('**/api/v1/accounts/1/actions/start', (route) => {
    startCalls += 1
    expect(route.request().method()).toBe('POST')
    return route.fulfill({ status: 202, json: jobFixture('start-missing', 'queued', 1) })
  })
  await page.route('**/api/v1/jobs/**', (route) => route.fulfill({
    status: 404,
    json: { error: { code: 'job_not_found', message: '任务不存在' } },
  }))

  await page.goto('/')
  await page.getByRole('button', { name: '开机' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '任务不存在' }).first()).toBeVisible()
  expect(startCalls).toBe(1)
})

test('instance stop surfaces the live job_not_found envelope', async ({ page }) => {
  let stopCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/accounts/1/actions/stop', (route) => {
    stopCalls += 1
    expect(route.request().method()).toBe('POST')
    return route.fulfill({ status: 202, json: jobFixture('stop-missing', 'queued', 1) })
  })
  await page.route('**/api/v1/jobs/**', (route) => route.fulfill({
    status: 404,
    json: { error: { code: 'job_not_found', message: '任务不存在' } },
  }))

  await page.goto('/')
  await page.getByRole('button', { name: '关机' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '任务不存在' }).first()).toBeVisible()
  expect(stopCalls).toBe(1)
})

test('instance start surfaces the live job unauthorized envelope', async ({ page }) => {
  let startCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page, {
    ...dashboardStatus,
    accounts: [{ ...dashboardAccount, instance_status: 'Stopped' }],
  })
  await page.route('**/api/v1/accounts/1/actions/start', (route) => {
    startCalls += 1
    expect(route.request().method()).toBe('POST')
    return route.fulfill({ status: 202, json: jobFixture('start-unauth', 'queued', 1) })
  })
  await page.route('**/api/v1/jobs/**', (route) => route.fulfill({
    status: 401,
    json: { error: { code: 'unauthorized', message: '请登录或提供有效 API Key' } },
  }))

  await page.goto('/')
  await page.getByRole('button', { name: '开机' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '请登录或提供有效 API Key' }).first()).toBeVisible()
  expect(startCalls).toBe(1)
})

test('instance start surfaces the live job forbidden envelope', async ({ page }) => {
  let startCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page, {
    ...dashboardStatus,
    accounts: [{ ...dashboardAccount, instance_status: 'Stopped' }],
  })
  await page.route('**/api/v1/accounts/1/actions/start', (route) => {
    startCalls += 1
    expect(route.request().method()).toBe('POST')
    return route.fulfill({ status: 202, json: jobFixture('start-forbidden', 'queued', 1) })
  })
  await page.route('**/api/v1/jobs/**', (route) => route.fulfill({
    status: 403,
    json: { error: { code: 'forbidden', message: 'API Key 权限不足' } },
  }))

  await page.goto('/')
  await page.getByRole('button', { name: '开机' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: 'API Key 权限不足' }).first()).toBeVisible()
  expect(startCalls).toBe(1)
})

test('instance start surfaces the live job internal_error envelope', async ({ page }) => {
  let startCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page, {
    ...dashboardStatus,
    accounts: [{ ...dashboardAccount, instance_status: 'Stopped' }],
  })
  await page.route('**/api/v1/accounts/1/actions/start', (route) => {
    startCalls += 1
    expect(route.request().method()).toBe('POST')
    return route.fulfill({ status: 202, json: jobFixture('start-internal', 'queued', 1) })
  })
  await page.route('**/api/v1/jobs/**', (route) => route.fulfill({
    status: 500,
    json: { error: { code: 'internal_error', message: '服务暂时不可用' } },
  }))

  await page.goto('/')
  await page.getByRole('button', { name: '开机' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '服务暂时不可用' }).first()).toBeVisible()
  expect(startCalls).toBe(1)
})

test('instance stop surfaces the live job unauthorized envelope', async ({ page }) => {
  let stopCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/accounts/1/actions/stop', (route) => {
    stopCalls += 1
    expect(route.request().method()).toBe('POST')
    return route.fulfill({ status: 202, json: jobFixture('stop-unauth', 'queued', 1) })
  })
  await page.route('**/api/v1/jobs/**', (route) => route.fulfill({
    status: 401,
    json: { error: { code: 'unauthorized', message: '请登录或提供有效 API Key' } },
  }))

  await page.goto('/')
  await page.getByRole('button', { name: '关机' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '请登录或提供有效 API Key' }).first()).toBeVisible()
  expect(stopCalls).toBe(1)
})

test('instance stop surfaces the live job forbidden envelope', async ({ page }) => {
  let stopCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/accounts/1/actions/stop', (route) => {
    stopCalls += 1
    expect(route.request().method()).toBe('POST')
    return route.fulfill({ status: 202, json: jobFixture('stop-forbidden', 'queued', 1) })
  })
  await page.route('**/api/v1/jobs/**', (route) => route.fulfill({
    status: 403,
    json: { error: { code: 'forbidden', message: 'API Key 权限不足' } },
  }))

  await page.goto('/')
  await page.getByRole('button', { name: '关机' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: 'API Key 权限不足' }).first()).toBeVisible()
  expect(stopCalls).toBe(1)
})

test('instance stop surfaces the live job internal_error envelope', async ({ page }) => {
  let stopCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/accounts/1/actions/stop', (route) => {
    stopCalls += 1
    expect(route.request().method()).toBe('POST')
    return route.fulfill({ status: 202, json: jobFixture('stop-internal', 'queued', 1) })
  })
  await page.route('**/api/v1/jobs/**', (route) => route.fulfill({
    status: 500,
    json: { error: { code: 'internal_error', message: '服务暂时不可用' } },
  }))

  await page.goto('/')
  await page.getByRole('button', { name: '关机' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '服务暂时不可用' }).first()).toBeVisible()
  expect(stopCalls).toBe(1)
})

test('instance stop surfaces the live job not_found envelope', async ({ page }) => {
  let stopCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/accounts/1/actions/stop', (route) => {
    stopCalls += 1
    expect(route.request().method()).toBe('POST')
    return route.fulfill({ status: 202, json: jobFixture('stop-not-found', 'queued', 1) })
  })
  await page.route('**/api/v1/jobs/**', (route) => route.fulfill({
    status: 404,
    json: { error: { code: 'not_found', message: '接口不存在' } },
  }))

  await page.goto('/')
  await page.getByRole('button', { name: '关机' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '接口不存在' }).first()).toBeVisible()
  expect(stopCalls).toBe(1)
})

test('instance start surfaces the live job not_found envelope', async ({ page }) => {
  let startCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page, {
    ...dashboardStatus,
    accounts: [{ ...dashboardAccount, instance_status: 'Stopped' }],
  })
  await page.route('**/api/v1/accounts/1/actions/start', (route) => {
    startCalls += 1
    expect(route.request().method()).toBe('POST')
    return route.fulfill({ status: 202, json: jobFixture('start-not-found', 'queued', 1) })
  })
  await page.route('**/api/v1/jobs/**', (route) => route.fulfill({
    status: 404,
    json: { error: { code: 'not_found', message: '接口不存在' } },
  }))

  await page.goto('/')
  await page.getByRole('button', { name: '开机' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '接口不存在' }).first()).toBeVisible()
  expect(startCalls).toBe(1)
})

test('settings email test surfaces the live job unauthorized envelope', async ({ page }) => {
  let testCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/notifications/test/email', (route) => {
    testCalls += 1
    expect(route.request().method()).toBe('POST')
    const job = jobFixture('notify-email-unauth', 'queued')
    job.type = 'test_notification'
    return route.fulfill({ status: 202, json: job })
  })
  await page.route('**/api/v1/jobs/**', (route) => route.fulfill({
    status: 401,
    json: { error: { code: 'unauthorized', message: '请登录或提供有效 API Key' } },
  }))

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: '发送测试' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '请登录或提供有效 API Key' }).first()).toBeVisible()
  expect(testCalls).toBe(1)
})

test('settings email test surfaces the live job forbidden envelope', async ({ page }) => {
  let testCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/notifications/test/email', (route) => {
    testCalls += 1
    expect(route.request().method()).toBe('POST')
    const job = jobFixture('notify-email-forbidden', 'queued')
    job.type = 'test_notification'
    return route.fulfill({ status: 202, json: job })
  })
  await page.route('**/api/v1/jobs/**', (route) => route.fulfill({
    status: 403,
    json: { error: { code: 'forbidden', message: 'API Key 权限不足' } },
  }))

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: '发送测试' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: 'API Key 权限不足' }).first()).toBeVisible()
  expect(testCalls).toBe(1)
})

test('settings email test surfaces the live job not_found envelope', async ({ page }) => {
  let testCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/notifications/test/email', (route) => {
    testCalls += 1
    expect(route.request().method()).toBe('POST')
    const job = jobFixture('notify-email-not-found', 'queued')
    job.type = 'test_notification'
    return route.fulfill({ status: 202, json: job })
  })
  await page.route('**/api/v1/jobs/**', (route) => route.fulfill({
    status: 404,
    json: { error: { code: 'not_found', message: '接口不存在' } },
  }))

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: '发送测试' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '接口不存在' }).first()).toBeVisible()
  expect(testCalls).toBe(1)
})

test('settings email test surfaces the live job internal_error envelope', async ({ page }) => {
  let testCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/notifications/test/email', (route) => {
    testCalls += 1
    expect(route.request().method()).toBe('POST')
    const job = jobFixture('notify-email-internal', 'queued')
    job.type = 'test_notification'
    return route.fulfill({ status: 202, json: job })
  })
  await page.route('**/api/v1/jobs/**', (route) => route.fulfill({
    status: 500,
    json: { error: { code: 'internal_error', message: '服务暂时不可用' } },
  }))

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: '发送测试' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '服务暂时不可用' }).first()).toBeVisible()
  expect(testCalls).toBe(1)
})

test('settings telegram test surfaces the live job unauthorized envelope', async ({ page }) => {
  let testCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/notifications/test/telegram', (route) => {
    testCalls += 1
    expect(route.request().method()).toBe('POST')
    const job = jobFixture('notify-telegram-unauth', 'queued')
    job.type = 'test_notification'
    return route.fulfill({ status: 202, json: job })
  })
  await page.route('**/api/v1/jobs/**', (route) => route.fulfill({
    status: 401,
    json: { error: { code: 'unauthorized', message: '请登录或提供有效 API Key' } },
  }))

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: 'Telegram' }).click()
  await page.getByRole('button', { name: '发送测试' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '请登录或提供有效 API Key' }).first()).toBeVisible()
  expect(testCalls).toBe(1)
})

test('settings telegram test surfaces the live job forbidden envelope', async ({ page }) => {
  let testCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/notifications/test/telegram', (route) => {
    testCalls += 1
    expect(route.request().method()).toBe('POST')
    const job = jobFixture('notify-telegram-forbidden', 'queued')
    job.type = 'test_notification'
    return route.fulfill({ status: 202, json: job })
  })
  await page.route('**/api/v1/jobs/**', (route) => route.fulfill({
    status: 403,
    json: { error: { code: 'forbidden', message: 'API Key 权限不足' } },
  }))

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: 'Telegram' }).click()
  await page.getByRole('button', { name: '发送测试' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: 'API Key 权限不足' }).first()).toBeVisible()
  expect(testCalls).toBe(1)
})

test('settings telegram test surfaces the live job not_found envelope', async ({ page }) => {
  let testCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/notifications/test/telegram', (route) => {
    testCalls += 1
    expect(route.request().method()).toBe('POST')
    const job = jobFixture('notify-telegram-not-found', 'queued')
    job.type = 'test_notification'
    return route.fulfill({ status: 202, json: job })
  })
  await page.route('**/api/v1/jobs/**', (route) => route.fulfill({
    status: 404,
    json: { error: { code: 'not_found', message: '接口不存在' } },
  }))

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: 'Telegram' }).click()
  await page.getByRole('button', { name: '发送测试' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '接口不存在' }).first()).toBeVisible()
  expect(testCalls).toBe(1)
})

test('settings telegram test surfaces the live job internal_error envelope', async ({ page }) => {
  let testCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/notifications/test/telegram', (route) => {
    testCalls += 1
    expect(route.request().method()).toBe('POST')
    const job = jobFixture('notify-telegram-internal', 'queued')
    job.type = 'test_notification'
    return route.fulfill({ status: 202, json: job })
  })
  await page.route('**/api/v1/jobs/**', (route) => route.fulfill({
    status: 500,
    json: { error: { code: 'internal_error', message: '服务暂时不可用' } },
  }))

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: 'Telegram' }).click()
  await page.getByRole('button', { name: '发送测试' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '服务暂时不可用' }).first()).toBeVisible()
  expect(testCalls).toBe(1)
})

test('settings webhook test surfaces the live job unauthorized envelope', async ({ page }) => {
  let testCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/notifications/test/webhook', (route) => {
    testCalls += 1
    expect(route.request().method()).toBe('POST')
    const job = jobFixture('notify-webhook-unauth', 'queued')
    job.type = 'test_notification'
    return route.fulfill({ status: 202, json: job })
  })
  await page.route('**/api/v1/jobs/**', (route) => route.fulfill({
    status: 401,
    json: { error: { code: 'unauthorized', message: '请登录或提供有效 API Key' } },
  }))

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: 'Webhook' }).click()
  await page.getByRole('button', { name: '发送测试' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '请登录或提供有效 API Key' }).first()).toBeVisible()
  expect(testCalls).toBe(1)
})

test('settings webhook test surfaces the live job forbidden envelope', async ({ page }) => {
  let testCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/notifications/test/webhook', (route) => {
    testCalls += 1
    expect(route.request().method()).toBe('POST')
    const job = jobFixture('notify-webhook-forbidden', 'queued')
    job.type = 'test_notification'
    return route.fulfill({ status: 202, json: job })
  })
  await page.route('**/api/v1/jobs/**', (route) => route.fulfill({
    status: 403,
    json: { error: { code: 'forbidden', message: 'API Key 权限不足' } },
  }))

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: 'Webhook' }).click()
  await page.getByRole('button', { name: '发送测试' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: 'API Key 权限不足' }).first()).toBeVisible()
  expect(testCalls).toBe(1)
})

test('settings webhook test surfaces the live job not_found envelope', async ({ page }) => {
  let testCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/notifications/test/webhook', (route) => {
    testCalls += 1
    expect(route.request().method()).toBe('POST')
    const job = jobFixture('notify-webhook-not-found', 'queued')
    job.type = 'test_notification'
    return route.fulfill({ status: 202, json: job })
  })
  await page.route('**/api/v1/jobs/**', (route) => route.fulfill({
    status: 404,
    json: { error: { code: 'not_found', message: '接口不存在' } },
  }))

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: 'Webhook' }).click()
  await page.getByRole('button', { name: '发送测试' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '接口不存在' }).first()).toBeVisible()
  expect(testCalls).toBe(1)
})

test('settings webhook test surfaces the live job internal_error envelope', async ({ page }) => {
  let testCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/notifications/test/webhook', (route) => {
    testCalls += 1
    expect(route.request().method()).toBe('POST')
    const job = jobFixture('notify-webhook-internal', 'queued')
    job.type = 'test_notification'
    return route.fulfill({ status: 202, json: job })
  })
  await page.route('**/api/v1/jobs/**', (route) => route.fulfill({
    status: 500,
    json: { error: { code: 'internal_error', message: '服务暂时不可用' } },
  }))

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: 'Webhook' }).click()
  await page.getByRole('button', { name: '发送测试' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '服务暂时不可用' }).first()).toBeVisible()
  expect(testCalls).toBe(1)
})

test('refresh-all job poll unauthorized surfaces the all-failed refresh message', async ({ page }) => {
  let refreshCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/accounts/refresh', (route) => {
    refreshCalls += 1
    expect(route.request().method()).toBe('POST')
    return route.fulfill({ status: 202, json: { jobs: [jobFixture('refresh-all-unauth', 'queued', 1)] } })
  })
  await page.route('**/api/v1/jobs/**', (route) => route.fulfill({
    status: 401,
    json: { error: { code: 'unauthorized', message: '请登录或提供有效 API Key' } },
  }))

  await page.goto('/')
  await page.getByRole('button', { name: '强制刷新全部实例' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '全部实例刷新失败，请查看运行日志' }).first()).toBeVisible()
  await expect(page.locator('.toast-stack')).not.toContainText('请登录或提供有效 API Key')
  expect(refreshCalls).toBe(1)
})

test('refresh-all job poll forbidden surfaces the all-failed refresh message', async ({ page }) => {
  let refreshCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/accounts/refresh', (route) => {
    refreshCalls += 1
    expect(route.request().method()).toBe('POST')
    return route.fulfill({ status: 202, json: { jobs: [jobFixture('refresh-all-forbidden', 'queued', 1)] } })
  })
  await page.route('**/api/v1/jobs/**', (route) => route.fulfill({
    status: 403,
    json: { error: { code: 'forbidden', message: 'API Key 权限不足' } },
  }))

  await page.goto('/')
  await page.getByRole('button', { name: '强制刷新全部实例' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '全部实例刷新失败，请查看运行日志' }).first()).toBeVisible()
  await expect(page.locator('.toast-stack')).not.toContainText('API Key 权限不足')
  expect(refreshCalls).toBe(1)
})

test('refresh-all job poll not_found surfaces the all-failed refresh message', async ({ page }) => {
  let refreshCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/accounts/refresh', (route) => {
    refreshCalls += 1
    expect(route.request().method()).toBe('POST')
    return route.fulfill({ status: 202, json: { jobs: [jobFixture('refresh-all-not-found', 'queued', 1)] } })
  })
  await page.route('**/api/v1/jobs/**', (route) => route.fulfill({
    status: 404,
    json: { error: { code: 'not_found', message: '接口不存在' } },
  }))

  await page.goto('/')
  await page.getByRole('button', { name: '强制刷新全部实例' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '全部实例刷新失败，请查看运行日志' }).first()).toBeVisible()
  await expect(page.locator('.toast-stack')).not.toContainText('接口不存在')
  expect(refreshCalls).toBe(1)
})

test('refresh-all job poll internal_error surfaces the all-failed refresh message', async ({ page }) => {
  let refreshCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/accounts/refresh', (route) => {
    refreshCalls += 1
    expect(route.request().method()).toBe('POST')
    return route.fulfill({ status: 202, json: { jobs: [jobFixture('refresh-all-internal', 'queued', 1)] } })
  })
  await page.route('**/api/v1/jobs/**', (route) => route.fulfill({
    status: 500,
    json: { error: { code: 'internal_error', message: '服务暂时不可用' } },
  }))

  await page.goto('/')
  await page.getByRole('button', { name: '强制刷新全部实例' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '全部实例刷新失败，请查看运行日志' }).first()).toBeVisible()
  await expect(page.locator('.toast-stack')).not.toContainText('服务暂时不可用')
  expect(refreshCalls).toBe(1)
})

test('settings heartbeat logs surface the live unauthorized envelope', async ({ page }) => {
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/logs**', (route) => {
    const tab = new URL(route.request().url()).searchParams.get('tab')
    if (tab === 'heartbeat') {
      return route.fulfill({
        status: 401,
        json: { error: { code: 'unauthorized', message: '请登录或提供有效 API Key' } },
      })
    }
    return route.fulfill({ json: { logs: [{ id: 1, type: 'audit', message: '动作日志', created_at: new Date().toISOString() }] } })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '日志' }).click()
  await expect(page.getByText('动作日志')).toBeVisible()
  await page.getByRole('button', { name: '心跳' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '请登录或提供有效 API Key' }).first()).toBeVisible()
  await expect(page.getByText('暂无日志')).toBeVisible()
  await expect(page.getByRole('heading', { name: '运行日志' })).toBeVisible()
})

test('settings heartbeat logs surface the live forbidden envelope', async ({ page }) => {
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/logs**', (route) => {
    const tab = new URL(route.request().url()).searchParams.get('tab')
    if (tab === 'heartbeat') {
      return route.fulfill({
        status: 403,
        json: { error: { code: 'forbidden', message: 'API Key 权限不足' } },
      })
    }
    return route.fulfill({ json: { logs: [{ id: 1, type: 'audit', message: '动作日志', created_at: new Date().toISOString() }] } })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '日志' }).click()
  await expect(page.getByText('动作日志')).toBeVisible()
  await page.getByRole('button', { name: '心跳' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: 'API Key 权限不足' }).first()).toBeVisible()
  await expect(page.getByText('暂无日志')).toBeVisible()
  await expect(page.getByRole('heading', { name: '运行日志' })).toBeVisible()
})

test('settings heartbeat logs surface the live not_found envelope', async ({ page }) => {
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/logs**', (route) => {
    const tab = new URL(route.request().url()).searchParams.get('tab')
    if (tab === 'heartbeat') {
      return route.fulfill({
        status: 404,
        json: { error: { code: 'not_found', message: '接口不存在' } },
      })
    }
    return route.fulfill({ json: { logs: [{ id: 1, type: 'audit', message: '动作日志', created_at: new Date().toISOString() }] } })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '日志' }).click()
  await expect(page.getByText('动作日志')).toBeVisible()
  await page.getByRole('button', { name: '心跳' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '接口不存在' }).first()).toBeVisible()
  await expect(page.getByText('暂无日志')).toBeVisible()
  await expect(page.getByRole('heading', { name: '运行日志' })).toBeVisible()
})

test('settings heartbeat logs surface the live internal_error envelope', async ({ page }) => {
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/logs**', (route) => {
    const tab = new URL(route.request().url()).searchParams.get('tab')
    if (tab === 'heartbeat') {
      return route.fulfill({
        status: 500,
        json: { error: { code: 'internal_error', message: '服务暂时不可用' } },
      })
    }
    return route.fulfill({ json: { logs: [{ id: 1, type: 'audit', message: '动作日志', created_at: new Date().toISOString() }] } })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '日志' }).click()
  await expect(page.getByText('动作日志')).toBeVisible()
  await page.getByRole('button', { name: '心跳' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '服务暂时不可用' }).first()).toBeVisible()
  await expect(page.getByText('暂无日志')).toBeVisible()
  await expect(page.getByRole('heading', { name: '运行日志' })).toBeVisible()
})

test('log heartbeat clear surfaces the live unauthorized envelope', async ({ page }) => {
  let clearCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/logs**', (route) => {
    const tab = new URL(route.request().url()).searchParams.get('tab')
    if (route.request().method() === 'DELETE') {
      expect(tab).toBe('heartbeat')
      clearCalls += 1
      return route.fulfill({
        status: 401,
        json: { error: { code: 'unauthorized', message: '请登录或提供有效 API Key' } },
      })
    }
    if (tab === 'heartbeat') {
      return route.fulfill({ json: { logs: [{ id: 2, type: 'heartbeat', message: '待清空心跳', created_at: new Date().toISOString() }] } })
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
  await expect(page.locator('.toast--error').filter({ hasText: '请登录或提供有效 API Key' }).first()).toBeVisible()
  await expect(page.getByText('待清空心跳')).toBeVisible()
  expect(clearCalls).toBe(1)
})

test('log heartbeat clear surfaces the live forbidden envelope', async ({ page }) => {
  let clearCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/logs**', (route) => {
    const tab = new URL(route.request().url()).searchParams.get('tab')
    if (route.request().method() === 'DELETE') {
      expect(tab).toBe('heartbeat')
      clearCalls += 1
      return route.fulfill({
        status: 403,
        json: { error: { code: 'forbidden', message: 'API Key 权限不足' } },
      })
    }
    if (tab === 'heartbeat') {
      return route.fulfill({ json: { logs: [{ id: 2, type: 'heartbeat', message: '待清空心跳', created_at: new Date().toISOString() }] } })
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
  await expect(page.locator('.toast--error').filter({ hasText: 'API Key 权限不足' }).first()).toBeVisible()
  await expect(page.getByText('待清空心跳')).toBeVisible()
  expect(clearCalls).toBe(1)
})

test('log heartbeat clear surfaces the live not_found envelope', async ({ page }) => {
  let clearCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/logs**', (route) => {
    const tab = new URL(route.request().url()).searchParams.get('tab')
    if (route.request().method() === 'DELETE') {
      expect(tab).toBe('heartbeat')
      clearCalls += 1
      return route.fulfill({
        status: 404,
        json: { error: { code: 'not_found', message: '接口不存在' } },
      })
    }
    if (tab === 'heartbeat') {
      return route.fulfill({ json: { logs: [{ id: 2, type: 'heartbeat', message: '待清空心跳', created_at: new Date().toISOString() }] } })
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
  await expect(page.locator('.toast--error').filter({ hasText: '接口不存在' }).first()).toBeVisible()
  await expect(page.getByText('待清空心跳')).toBeVisible()
  expect(clearCalls).toBe(1)
})

test('log heartbeat clear surfaces the live internal_error envelope', async ({ page }) => {
  let clearCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/logs**', (route) => {
    const tab = new URL(route.request().url()).searchParams.get('tab')
    if (route.request().method() === 'DELETE') {
      expect(tab).toBe('heartbeat')
      clearCalls += 1
      return route.fulfill({
        status: 500,
        json: { error: { code: 'internal_error', message: '服务暂时不可用' } },
      })
    }
    if (tab === 'heartbeat') {
      return route.fulfill({ json: { logs: [{ id: 2, type: 'heartbeat', message: '待清空心跳', created_at: new Date().toISOString() }] } })
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
  await expect(page.locator('.toast--error').filter({ hasText: '服务暂时不可用' }).first()).toBeVisible()
  await expect(page.getByText('待清空心跳')).toBeVisible()
  expect(clearCalls).toBe(1)
})

test('log heartbeat clear surfaces the csrf_failed envelope', async ({ page }) => {
  let clearCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/logs**', (route) => {
    const tab = new URL(route.request().url()).searchParams.get('tab')
    if (route.request().method() === 'DELETE') {
      expect(tab).toBe('heartbeat')
      clearCalls += 1
      return route.fulfill({
        status: 403,
        json: { error: { code: 'csrf_failed', message: 'CSRF 校验失败' } },
      })
    }
    if (tab === 'heartbeat') {
      return route.fulfill({ json: { logs: [{ id: 2, type: 'heartbeat', message: '待清空心跳', created_at: new Date().toISOString() }] } })
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
  await expect(page.locator('.toast--error').filter({ hasText: 'CSRF 校验失败' }).first()).toBeVisible()
  await expect(page.getByText('待清空心跳')).toBeVisible()
  expect(clearCalls).toBe(1)
})

test('log heartbeat clear surfaces the logs_failed envelope', async ({ page }) => {
  let clearCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/logs**', (route) => {
    const tab = new URL(route.request().url()).searchParams.get('tab')
    if (route.request().method() === 'DELETE') {
      expect(tab).toBe('heartbeat')
      clearCalls += 1
      return route.fulfill({
        status: 500,
        json: { error: { code: 'logs_failed', message: '日志操作失败' } },
      })
    }
    if (tab === 'heartbeat') {
      return route.fulfill({ json: { logs: [{ id: 2, type: 'heartbeat', message: '待清空心跳', created_at: new Date().toISOString() }] } })
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
  await expect(page.locator('.toast--error').filter({ hasText: '日志操作失败' }).first()).toBeVisible()
  await expect(page.getByText('待清空心跳')).toBeVisible()
  expect(clearCalls).toBe(1)
})

test('settings heartbeat logs surface the logs_failed envelope', async ({ page }) => {
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/logs**', (route) => {
    const tab = new URL(route.request().url()).searchParams.get('tab')
    if (tab === 'heartbeat') {
      return route.fulfill({
        status: 500,
        json: { error: { code: 'logs_failed', message: '日志操作失败' } },
      })
    }
    return route.fulfill({ json: { logs: [{ id: 1, type: 'audit', message: '动作日志', created_at: new Date().toISOString() }] } })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '日志' }).click()
  await expect(page.getByText('动作日志')).toBeVisible()
  await page.getByRole('button', { name: '心跳' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '日志操作失败' }).first()).toBeVisible()
  await expect(page.getByText('暂无日志')).toBeVisible()
  await expect(page.getByRole('heading', { name: '运行日志' })).toBeVisible()
})

test('settings email test surfaces the job_not_found envelope', async ({ page }) => {
  let testCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/notifications/test/email', (route) => {
    testCalls += 1
    expect(route.request().method()).toBe('POST')
    const job = jobFixture('notify-email-missing', 'queued')
    job.type = 'test_notification'
    return route.fulfill({ status: 202, json: job })
  })
  await page.route('**/api/v1/jobs/**', (route) => route.fulfill({
    status: 404,
    json: { error: { code: 'job_not_found', message: '任务不存在' } },
  }))

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: '发送测试' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '任务不存在' }).first()).toBeVisible()
  expect(testCalls).toBe(1)
})

test('settings telegram test surfaces the job_not_found envelope', async ({ page }) => {
  let testCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/notifications/test/telegram', (route) => {
    testCalls += 1
    expect(route.request().method()).toBe('POST')
    const job = jobFixture('notify-telegram-missing', 'queued')
    job.type = 'test_notification'
    return route.fulfill({ status: 202, json: job })
  })
  await page.route('**/api/v1/jobs/**', (route) => route.fulfill({
    status: 404,
    json: { error: { code: 'job_not_found', message: '任务不存在' } },
  }))

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: 'Telegram' }).click()
  await page.getByRole('button', { name: '发送测试' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '任务不存在' }).first()).toBeVisible()
  expect(testCalls).toBe(1)
})

test('settings webhook test surfaces the job_not_found envelope', async ({ page }) => {
  let testCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/notifications/test/webhook', (route) => {
    testCalls += 1
    expect(route.request().method()).toBe('POST')
    const job = jobFixture('notify-webhook-missing', 'queued')
    job.type = 'test_notification'
    return route.fulfill({ status: 202, json: job })
  })
  await page.route('**/api/v1/jobs/**', (route) => route.fulfill({
    status: 404,
    json: { error: { code: 'job_not_found', message: '任务不存在' } },
  }))

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: 'Webhook' }).click()
  await page.getByRole('button', { name: '发送测试' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '任务不存在' }).first()).toBeVisible()
  expect(testCalls).toBe(1)
})

test('refresh-all job poll job_not_found surfaces the all-failed refresh message', async ({ page }) => {
  let refreshCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/accounts/refresh', (route) => {
    refreshCalls += 1
    expect(route.request().method()).toBe('POST')
    return route.fulfill({ status: 202, json: { jobs: [jobFixture('refresh-all-missing', 'queued', 1)] } })
  })
  await page.route('**/api/v1/jobs/**', (route) => route.fulfill({
    status: 404,
    json: { error: { code: 'job_not_found', message: '任务不存在' } },
  }))

  await page.goto('/')
  await page.getByRole('button', { name: '强制刷新全部实例' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '全部实例刷新失败，请查看运行日志' }).first()).toBeVisible()
  await expect(page.locator('.toast-stack')).not.toContainText('任务不存在')
  expect(refreshCalls).toBe(1)
})

test('refresh-all job poll job_failed surfaces the all-failed refresh message', async ({ page }) => {
  let refreshCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/accounts/refresh', (route) => {
    refreshCalls += 1
    expect(route.request().method()).toBe('POST')
    return route.fulfill({ status: 202, json: { jobs: [jobFixture('refresh-all-job-failed', 'queued', 1)] } })
  })
  await page.route('**/api/v1/jobs/**', (route) => route.fulfill({
    status: 500,
    json: { error: { code: 'job_failed', message: '任务查询失败' } },
  }))

  await page.goto('/')
  await page.getByRole('button', { name: '强制刷新全部实例' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '全部实例刷新失败，请查看运行日志' }).first()).toBeVisible()
  await expect(page.locator('.toast-stack')).not.toContainText('任务查询失败')
  expect(refreshCalls).toBe(1)
})

test('history chart surfaces the live missing-account not_found envelope', async ({ page }) => {
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/accounts/1/history', (route) => route.fulfill({
    status: 404,
    json: { error: { code: 'not_found', message: '账号不存在' } },
  }))

  await page.goto('/')
  await page.getByRole('button', { name: '查看历史流量' }).click()
  await expect(page.getByRole('alert')).toContainText('账号不存在')
  await expect(page.locator('.chart-area .recharts-wrapper')).toHaveCount(0)
})

test('failed refresh job with missing-account store error uses generic toast', async ({ page }) => {
  const leaked = 'account id is invalid'
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/accounts/1/refresh', (route) => {
    expect(route.request().method()).toBe('POST')
    return route.fulfill({ status: 202, json: jobFixture('refresh-missing-account', 'queued', 1) })
  })
  await page.route('**/api/v1/jobs/**', (route) => {
    const failed = jobFixture('refresh-missing-account', 'failed', 1)
    failed.error = leaked
    return route.fulfill({ json: failed })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '刷新实例' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: JOB_FAILED_USER_MESSAGE }).first()).toBeVisible()
  await expect(page.locator('.toast-stack')).not.toContainText(leaked)
})

test('failed start job with missing-account store error uses generic toast', async ({ page }) => {
  const leaked = 'account id is invalid'
  await mockInitStatus(page, true)
  await mockDashboardReads(page, {
    ...dashboardStatus,
    accounts: [{ ...dashboardAccount, instance_status: 'Stopped' }],
  })
  await page.route('**/api/v1/accounts/1/actions/start', (route) => {
    expect(route.request().method()).toBe('POST')
    return route.fulfill({ status: 202, json: jobFixture('start-missing-account', 'queued', 1) })
  })
  await page.route('**/api/v1/jobs/**', (route) => {
    const failed = jobFixture('start-missing-account', 'failed', 1)
    failed.error = leaked
    return route.fulfill({ json: failed })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '开机' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: JOB_FAILED_USER_MESSAGE }).first()).toBeVisible()
  await expect(page.locator('.toast-stack')).not.toContainText(leaked)
})

test('failed stop job with missing-account store error uses generic toast', async ({ page }) => {
  const leaked = 'account id is invalid'
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/accounts/1/actions/stop', (route) => {
    expect(route.request().method()).toBe('POST')
    return route.fulfill({ status: 202, json: jobFixture('stop-missing-account', 'queued', 1) })
  })
  await page.route('**/api/v1/jobs/**', (route) => {
    const failed = jobFixture('stop-missing-account', 'failed', 1)
    failed.error = leaked
    return route.fulfill({ json: failed })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '关机' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: JOB_FAILED_USER_MESSAGE }).first()).toBeVisible()
  await expect(page.locator('.toast-stack')).not.toContainText(leaked)
})

test('failed email notify job with missing-account store error uses generic toast', async ({ page }) => {
  const leaked = 'account id is invalid'
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/notifications/test/email', (route) => {
    expect(route.request().method()).toBe('POST')
    const job = jobFixture('notify-email-missing-account', 'queued')
    job.type = 'test_notification'
    return route.fulfill({ status: 202, json: job })
  })
  await page.route('**/api/v1/jobs/**', (route) => {
    const failed = jobFixture('notify-email-missing-account', 'failed')
    failed.type = 'test_notification'
    failed.error = leaked
    return route.fulfill({ json: failed })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: '发送测试' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: JOB_FAILED_USER_MESSAGE }).first()).toBeVisible()
  await expect(page.locator('.toast-stack')).not.toContainText(leaked)
})

test('failed telegram notify job with missing-account store error uses generic toast', async ({ page }) => {
  const leaked = 'account id is invalid'
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/notifications/test/telegram', (route) => {
    expect(route.request().method()).toBe('POST')
    const job = jobFixture('notify-telegram-missing-account', 'queued')
    job.type = 'test_notification'
    return route.fulfill({ status: 202, json: job })
  })
  await page.route('**/api/v1/jobs/**', (route) => {
    const failed = jobFixture('notify-telegram-missing-account', 'failed')
    failed.type = 'test_notification'
    failed.error = leaked
    return route.fulfill({ json: failed })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: 'Telegram' }).click()
  await page.getByRole('button', { name: '发送测试' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: JOB_FAILED_USER_MESSAGE }).first()).toBeVisible()
  await expect(page.locator('.toast-stack')).not.toContainText(leaked)
})

test('failed webhook notify job with missing-account store error uses generic toast', async ({ page }) => {
  const leaked = 'account id is invalid'
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/notifications/test/webhook', (route) => {
    expect(route.request().method()).toBe('POST')
    const job = jobFixture('notify-webhook-missing-account', 'queued')
    job.type = 'test_notification'
    return route.fulfill({ status: 202, json: job })
  })
  await page.route('**/api/v1/jobs/**', (route) => {
    const failed = jobFixture('notify-webhook-missing-account', 'failed')
    failed.type = 'test_notification'
    failed.error = leaked
    return route.fulfill({ json: failed })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: 'Webhook' }).click()
  await page.getByRole('button', { name: '发送测试' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: JOB_FAILED_USER_MESSAGE }).first()).toBeVisible()
  await expect(page.locator('.toast-stack')).not.toContainText(leaked)
})

test('refresh-all missing-account store error uses all-failed toast', async ({ page }) => {
  const leaked = 'account id is invalid'
  let refreshCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/accounts/refresh', (route) => {
    refreshCalls += 1
    expect(route.request().method()).toBe('POST')
    return route.fulfill({ status: 202, json: { jobs: [jobFixture('refresh-all-missing-account', 'queued', 1)] } })
  })
  await page.route('**/api/v1/jobs/**', (route) => {
    const failed = jobFixture('refresh-all-missing-account', 'failed', 1)
    failed.error = leaked
    return route.fulfill({ json: failed })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '强制刷新全部实例' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: '全部实例刷新失败，请查看运行日志' }).first()).toBeVisible()
  await expect(page.locator('.toast-stack')).not.toContainText(leaked)
  expect(refreshCalls).toBe(1)
})

test('settings API key create surfaces the live past expiry api_key_failed envelope', async ({ page }) => {
  const expiresLocal = '2020-01-01T00:00'
  let createCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/api-keys', (route) => {
    if (route.request().method() === 'POST') {
      createCalls += 1
      const body = JSON.parse(route.request().postData() || '{}') as { expires_at?: string }
      expect(new Date(body.expires_at || '').toISOString()).toBe(new Date(expiresLocal).toISOString())
      return route.fulfill({
        status: 400,
        json: { error: { code: 'api_key_failed', message: 'API Key 创建失败' } },
      })
    }
    return route.fulfill({ json: { keys: [] } })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: 'API Key' }).click()
  await page.getByLabel('过期时间（可选）').fill(expiresLocal)
  await page.getByRole('button', { name: '创建 Key' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: 'API Key 创建失败' }).first()).toBeVisible()
  await expect(page.locator('.toast-stack')).not.toContainText('api key expiry must be in the future')
  await expect(page.getByText('仅显示一次')).toHaveCount(0)
  expect(createCalls).toBe(1)
})

test('settings API key revoke surfaces the live missing-key not_found envelope', async ({ page }) => {
  const existing = {
    id: 17,
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
      status: 404,
      json: { error: { code: 'not_found', message: 'API Key 不存在' } },
    })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: 'API Key' }).click()
  await page.getByRole('button', { name: '撤销' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: 'API Key 不存在' }).first()).toBeVisible()
  await expect(page.locator('.key-row')).toContainText('桌面小组件')
  expect(revokeCalls).toBe(1)
})

test('admin passkey delete surfaces the live missing-passkey not_found envelope', async ({ page }) => {
  const existing = { id: 9, name: '办公室电脑', created_at: new Date().toISOString() }
  let deleteCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/admin/passkeys', (route) => route.fulfill({ json: { passkeys: [existing] } }))
  await page.route('**/api/v1/admin/passkeys/**', (route) => {
    deleteCalls += 1
    expect(route.request().method()).toBe('DELETE')
    return route.fulfill({
      status: 404,
      json: { error: { code: 'not_found', message: 'Passkey 不存在' } },
    })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '管理员' }).click()
  await page.getByRole('button', { name: '删除 Passkey' }).click()
  await expect(page.locator('.toast--error').filter({ hasText: 'Passkey 不存在' }).first()).toBeVisible()
  await expect(page.locator('.passkey-row')).toContainText('办公室电脑')
  expect(deleteCalls).toBe(1)
})

test('instance start timeout hides missing-account store error', async ({ page }) => {
  const leaked = 'account id is invalid'
  await page.clock.install()
  await mockInitStatus(page, true)
  await mockDashboardReads(page, {
    ...dashboardStatus,
    accounts: [{ ...dashboardAccount, instance_status: 'Stopped' }],
  })
  await page.route('**/api/v1/accounts/1/actions/start', (route) => {
    expect(route.request().method()).toBe('POST')
    return route.fulfill({ status: 202, json: jobFixture('start-timeout-missing', 'queued', 1) })
  })
  await page.route('**/api/v1/jobs/**', (route) => {
    const queued = jobFixture('start-timeout-missing', 'queued', 1)
    queued.error = leaked
    return route.fulfill({ json: queued })
  })

  await page.goto('/')
  const jobPolled = page.waitForRequest('**/api/v1/jobs/**')
  await page.getByRole('button', { name: '开机' }).click()
  await jobPolled
  await page.clock.fastForward(71_000)
  await expect(page.locator('.toast--error').filter({ hasText: '任务仍在后台执行，请稍后刷新' }).first()).toBeVisible()
  await expect(page.locator('.toast-stack')).not.toContainText(leaked)
})

test('instance stop timeout hides missing-account store error', async ({ page }) => {
  const leaked = 'account id is invalid'
  await page.clock.install()
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/accounts/1/actions/stop', (route) => {
    expect(route.request().method()).toBe('POST')
    return route.fulfill({ status: 202, json: jobFixture('stop-timeout-missing', 'queued', 1) })
  })
  await page.route('**/api/v1/jobs/**', (route) => {
    const queued = jobFixture('stop-timeout-missing', 'queued', 1)
    queued.error = leaked
    return route.fulfill({ json: queued })
  })

  await page.goto('/')
  const jobPolled = page.waitForRequest('**/api/v1/jobs/**')
  await page.getByRole('button', { name: '关机' }).click()
  await jobPolled
  await page.clock.fastForward(71_000)
  await expect(page.locator('.toast--error').filter({ hasText: '任务仍在后台执行，请稍后刷新' }).first()).toBeVisible()
  await expect(page.locator('.toast-stack')).not.toContainText(leaked)
})

test('instance refresh timeout hides missing-account store error', async ({ page }) => {
  const leaked = 'account id is invalid'
  await page.clock.install()
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/accounts/1/refresh', (route) => {
    expect(route.request().method()).toBe('POST')
    return route.fulfill({ status: 202, json: jobFixture('refresh-timeout-missing', 'queued', 1) })
  })
  await page.route('**/api/v1/jobs/**', (route) => {
    const queued = jobFixture('refresh-timeout-missing', 'queued', 1)
    queued.error = leaked
    return route.fulfill({ json: queued })
  })

  await page.goto('/')
  const jobPolled = page.waitForRequest('**/api/v1/jobs/**')
  await page.getByRole('button', { name: '刷新实例' }).click()
  await jobPolled
  await page.clock.fastForward(71_000)
  await expect(page.locator('.toast--error').filter({ hasText: '任务仍在后台执行，请稍后刷新' }).first()).toBeVisible()
  await expect(page.locator('.toast-stack')).not.toContainText(leaked)
})

test('email notify timeout hides missing-account store error', async ({ page }) => {
  const leaked = 'account id is invalid'
  await page.clock.install()
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/notifications/test/email', (route) => {
    expect(route.request().method()).toBe('POST')
    const job = jobFixture('notify-email-timeout-missing', 'queued')
    job.type = 'test_notification'
    return route.fulfill({ status: 202, json: job })
  })
  await page.route('**/api/v1/jobs/**', (route) => {
    const queued = jobFixture('notify-email-timeout-missing', 'queued')
    queued.type = 'test_notification'
    queued.error = leaked
    return route.fulfill({ json: queued })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  const jobPolled = page.waitForRequest('**/api/v1/jobs/**')
  await page.getByRole('button', { name: '发送测试' }).click()
  await jobPolled
  await page.clock.fastForward(71_000)
  await expect(page.locator('.toast--error').filter({ hasText: '任务仍在后台执行，请稍后刷新' }).first()).toBeVisible()
  await expect(page.locator('.toast-stack')).not.toContainText(leaked)
})

test('telegram notify timeout hides missing-account store error', async ({ page }) => {
  const leaked = 'account id is invalid'
  await page.clock.install()
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/notifications/test/telegram', (route) => {
    expect(route.request().method()).toBe('POST')
    const job = jobFixture('notify-telegram-timeout-missing', 'queued')
    job.type = 'test_notification'
    return route.fulfill({ status: 202, json: job })
  })
  await page.route('**/api/v1/jobs/**', (route) => {
    const queued = jobFixture('notify-telegram-timeout-missing', 'queued')
    queued.type = 'test_notification'
    queued.error = leaked
    return route.fulfill({ json: queued })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: 'Telegram' }).click()
  const jobPolled = page.waitForRequest('**/api/v1/jobs/**')
  await page.getByRole('button', { name: '发送测试' }).click()
  await jobPolled
  await page.clock.fastForward(71_000)
  await expect(page.locator('.toast--error').filter({ hasText: '任务仍在后台执行，请稍后刷新' }).first()).toBeVisible()
  await expect(page.locator('.toast-stack')).not.toContainText(leaked)
})

test('webhook notify timeout hides missing-account store error', async ({ page }) => {
  const leaked = 'account id is invalid'
  await page.clock.install()
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/notifications/test/webhook', (route) => {
    expect(route.request().method()).toBe('POST')
    const job = jobFixture('notify-webhook-timeout-missing', 'queued')
    job.type = 'test_notification'
    return route.fulfill({ status: 202, json: job })
  })
  await page.route('**/api/v1/jobs/**', (route) => {
    const queued = jobFixture('notify-webhook-timeout-missing', 'queued')
    queued.type = 'test_notification'
    queued.error = leaked
    return route.fulfill({ json: queued })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '通知', exact: true }).click()
  await page.getByRole('button', { name: 'Webhook' }).click()
  const jobPolled = page.waitForRequest('**/api/v1/jobs/**')
  await page.getByRole('button', { name: '发送测试' }).click()
  await jobPolled
  await page.clock.fastForward(71_000)
  await expect(page.locator('.toast--error').filter({ hasText: '任务仍在后台执行，请稍后刷新' }).first()).toBeVisible()
  await expect(page.locator('.toast-stack')).not.toContainText(leaked)
})

test('refresh-all timeout hides missing-account store error', async ({ page }) => {
  const leaked = 'account id is invalid'
  let refreshCalls = 0
  await page.clock.install()
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/accounts/refresh', (route) => {
    refreshCalls += 1
    expect(route.request().method()).toBe('POST')
    return route.fulfill({ status: 202, json: { jobs: [jobFixture('refresh-all-timeout-missing', 'queued', 1)] } })
  })
  await page.route('**/api/v1/jobs/**', (route) => {
    const queued = jobFixture('refresh-all-timeout-missing', 'queued', 1)
    queued.error = leaked
    return route.fulfill({ json: queued })
  })

  await page.goto('/')
  const jobPolled = page.waitForRequest('**/api/v1/jobs/**')
  await page.getByRole('button', { name: '强制刷新全部实例' }).click()
  await jobPolled
  await page.clock.fastForward(71_000)
  await expect(page.locator('.toast--error').filter({ hasText: '全部实例刷新失败，请查看运行日志' }).first()).toBeVisible()
  await expect(page.locator('.toast-stack')).not.toContainText(leaked)
  expect(refreshCalls).toBe(1)
})

test('settings API key create stays disabled for whitespace names', async ({ page }) => {
  let createCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/api-keys', (route) => {
    if (route.request().method() === 'POST') {
      createCalls += 1
      return route.fulfill({ status: 201, json: { key: { id: 1, name: 'x', scopes: ['widget:read'], created_at: new Date().toISOString() }, token: 'cdt_token' } })
    }
    return route.fulfill({ json: { keys: [] } })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: 'API Key' }).click()
  await page.getByLabel('名称').fill('   ')
  await expect(page.getByRole('button', { name: '创建 Key' })).toBeDisabled()
  expect(createCalls).toBe(0)
})

test('settings API key create posts a trimmed name', async ({ page }) => {
  const created = {
    id: 18,
    name: '桌面小组件',
    scopes: ['widget:read'],
    created_at: new Date().toISOString(),
  }
  let createCalls = 0
  await mockInitStatus(page, true)
  await mockDashboardReads(page)
  await page.route('**/api/v1/api-keys', (route) => {
    if (route.request().method() === 'POST') {
      createCalls += 1
      expect(JSON.parse(route.request().postData() || '{}')).toEqual({
        name: '桌面小组件',
        scopes: ['widget:read'],
      })
      return route.fulfill({ status: 201, json: { key: created, token: 'cdt_trimmed_token' } })
    }
    return route.fulfill({ json: { keys: createCalls > 0 ? [created] : [] } })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: 'API Key' }).click()
  await page.getByLabel('名称').fill('  桌面小组件  ')
  await page.getByRole('button', { name: '创建 Key' }).click()
  await expect(page.getByText('仅显示一次')).toBeVisible()
  await expect(page.locator('.key-row')).toContainText('桌面小组件')
  expect(createCalls).toBe(1)
})

test('boot config_failed surfaces the live fatal envelope', async ({ page }) => {
  await mockInitStatus(page, true)
  await page.route('**/api/v1/status', (route) => route.fulfill({ json: dashboardStatus }))
  await page.route('**/api/v1/config', (route) => route.fulfill({
    status: 500,
    json: { error: { code: 'config_failed', message: '配置加载失败' } },
  }))

  await page.goto('/')
  await expect(page.getByRole('heading', { name: '控制台暂时不可用' })).toBeVisible()
  await expect(page.getByText('配置加载失败')).toBeVisible()
})

test('boot status_failed surfaces the live fatal envelope', async ({ page }) => {
  await mockInitStatus(page, true)
  await page.route('**/api/v1/status', (route) => route.fulfill({
    status: 500,
    json: { error: { code: 'status_failed', message: '状态加载失败' } },
  }))
  await page.route('**/api/v1/config', (route) => route.fulfill({ json: dashboardConfig }))

  await page.goto('/')
  await expect(page.getByRole('heading', { name: '控制台暂时不可用' })).toBeVisible()
  await expect(page.getByText('状态加载失败')).toBeVisible()
})

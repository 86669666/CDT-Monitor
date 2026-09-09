import { expect, type Page } from '@playwright/test'
import type { AccountSummary, Config, History, Job, JobStatus, StatusResponse } from '../src/types'

export const TEST_PASSWORD = 'Visual-Test-Password-42!'

export const CONFIG_OBJECT_KEYS = [
  'admin_password',
  'traffic_threshold',
  'enable_schedule_notification',
  'shutdown_mode',
  'threshold_action',
  'keep_alive',
  'api_interval',
  'enable_billing',
  'timezone',
  'notifications',
  'accounts',
] as const

export const ACCOUNT_OBJECT_KEYS = [
  'id',
  'access_key_id',
  'access_key_secret',
  'secret_configured',
  'region_id',
  'instance_id',
  'max_traffic',
  'schedule_enabled',
  'start_time',
  'stop_time',
  'remark',
  'site_type',
  'traffic_used',
  'instance_status',
  'updated_at',
  'last_keep_alive_at',
  'monthly_cost',
  'balance',
  'currency',
  'billing_error',
  'billing_updated_at',
] as const

export const dashboardConfig: Config = {
  traffic_threshold: 95,
  enable_schedule_notification: false,
  shutdown_mode: 'KeepCharging',
  threshold_action: 'stop_and_notify',
  keep_alive: false,
  api_interval: 600,
  enable_billing: true,
  timezone: 'Asia/Shanghai',
  notifications: {
    email: { enabled: false, to: '', host: '', port: 465, username: '', password_configured: false, security: 'ssl' },
    telegram: { enabled: false, token_configured: false, chat_id: '', proxy_type: 'none', proxy_url: '', proxy_ip: '', proxy_port: '', proxy_user: '', proxy_password_configured: false },
    webhook: { enabled: false, url: '', method: 'GET', request_type: 'JSON', body: '', secret_configured: false, headers_configured: false },
  },
  accounts: [{
    id: 1,
    access_key_id: 'LTAI5test',
    secret_configured: true,
    region_id: 'cn-hongkong',
    instance_id: 'i-test',
    max_traffic: 200,
    schedule_enabled: false,
    start_time: '08:00',
    stop_time: '23:30',
    remark: '香港测试节点',
    site_type: 'china',
  }],
}

export const dashboardAccount: AccountSummary = {
  id: 1,
  account: 'LTAI5te***',
  remark: '香港测试节点',
  region: 'cn-hongkong',
  region_name: '中国香港',
  flow_total: 200,
  flow_used: 12.5,
  percentage: 6.25,
  threshold: 95,
  over_threshold: false,
  instance_status: 'Running',
  last_updated: new Date().toISOString(),
  stale: false,
  monthly_cost: 23.456,
  balance: 123.45,
  currency: 'CNY',
}

export const dashboardStatus: StatusResponse = {
  accounts: [dashboardAccount],
  system_last_run: new Date().toISOString(),
}

export const emptyHistory: History = { hourly: [], daily: [] }

export function jobFixture(id: string, status: JobStatus, accountId = 1): Job {
  const now = new Date().toISOString()
  return {
    id,
    type: 'refresh_account',
    account_id: accountId,
    status,
    attempts: status === 'queued' ? 0 : 1,
    max_attempts: 3,
    available_at: now,
    created_at: now,
    updated_at: now,
  }
}

export function expectKnownKeys(record: Record<string, unknown>, allowed: readonly string[]) {
  for (const key of Object.keys(record)) {
    expect(allowed, `unexpected API field ${key}`).toContain(key)
  }
}

export async function mockInitStatus(page: Page, initialized: boolean) {
  await page.route('**/api/v1/system/init-status', (route) => route.fulfill({ json: { initialized } }))
}

export async function mockDashboardReads(page: Page, status: StatusResponse = dashboardStatus, config: Config = dashboardConfig) {
  await page.route('**/api/v1/status', (route) => route.fulfill({ json: status }))
  await page.route('**/api/v1/config', (route) => route.fulfill({ json: config }))
}

export async function mockUnauthorizedSession(page: Page) {
  const error = { error: { code: 'unauthorized', message: '请登录或提供有效 API Key' } }
  await page.route('**/api/v1/status', (route) => route.fulfill({ status: 401, json: error }))
  await page.route('**/api/v1/config', (route) => route.fulfill({ status: 401, json: error }))
}

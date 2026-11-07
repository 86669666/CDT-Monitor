import { expect, test } from '@playwright/test'
import type { Page } from '@playwright/test'
import { defaultConfig, emptyAccount } from '../src/types'

async function fixture(page: Page, addressTarget = 'i-current') {
  const account = { ...emptyAccount(), id: 1, access_key_id: 'LTAItest', secret_configured: true, region_id: 'cn-beijing', instance_id: 'i-current', remark: '测试实例', max_traffic: 20 }
  const config = { ...defaultConfig(), threshold_action: 'notify_only', accounts: [account] }
  const now = new Date().toISOString()
  const status = { accounts: [{ id: 1, account: 'LTAItes***', remark: '测试实例', region: 'cn-beijing', region_name: '北京', flow_total: 20, flow_used: 1, percentage: 5, threshold: 95, over_threshold: false, instance_status: 'Running', last_updated: now, stale: false, traffic_pool_id: 'pool-1', traffic_pool_class: 'china', traffic_pool_instance_count: 1, traffic_pool_quota_conflict: false, traffic_updated_at: now, traffic_stale: false }], system_last_run: now }
  await page.route('**/api/v1/system/init-status', route => route.fulfill({ json: { initialized: true } }))
  await page.route('**/api/v1/config', route => route.fulfill({ json: config }))
  await page.route('**/api/v1/status', route => route.fulfill({ json: status }))
  await page.route('**/api/v1/accounts/instance-addresses', route => route.fulfill({ json: { instances: [{ account_id: 1, access_key_id: 'LTAItest', region_id: 'cn-beijing', instance_id: addressTarget, public_ipv4: '203.0.113.7', ipv6: '2001:db8::1', observed_at: now, observed: true, stale: false }] } }))
}

test('theme switching preserves dashboard and canceling power confirmation', async ({ page }) => {
  await fixture(page)
  let controls = 0
  await page.route('**/api/v1/accounts/*/actions/*', route => { controls++; return route.fulfill({ status: 202, json: { id: 'fixture-job' } }) })
  await page.emulateMedia({ colorScheme: 'dark' })
  await page.goto('/cdt/')
  await expect(page.getByRole('heading', { name: '资源控制台' })).toBeVisible()
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark')
  await expect(page.getByText('203.0.113.7')).toBeVisible()
  await page.getByRole('button', { name: '关机', exact: true }).click()
  await expect(page.getByRole('alertdialog', { name: '确认关机？' })).toBeVisible()
  await page.keyboard.press('Escape')
  await expect(page.getByRole('alertdialog')).toHaveCount(0)
  expect(controls).toBe(0)
  await page.getByRole('button', { name: '外观：跟随系统' }).click()
  await page.getByRole('menuitemradio', { name: '浅色' }).click()
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light')
  await page.reload()
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light')
})

test('addresses for an old target are never displayed on the current instance', async ({ page }) => {
  await fixture(page, 'i-previous')
  await page.goto('/')
  await expect(page.getByRole('heading', { name: '资源控制台' })).toBeVisible()
  await expect(page.getByText('实例地址待同步')).toBeVisible()
  await expect(page.getByText('203.0.113.7')).toHaveCount(0)
  for (const changed of [{ access_key_id: 'other-key', region_id: 'cn-beijing' }, { access_key_id: 'LTAItest', region_id: 'cn-shanghai' }]) {
    await page.route('**/api/v1/accounts/instance-addresses', route => route.fulfill({ json: { instances: [{ account_id: 1, ...changed, instance_id: 'i-current', public_ipv4: '203.0.113.7', ipv6: '', observed_at: new Date().toISOString(), observed: true, stale: false }] } }))
    await page.reload()
    await expect(page.getByText('实例地址待同步')).toBeVisible()
    await expect(page.getByText('203.0.113.7')).toHaveCount(0)
  }
})

test('imported instance uses server-assigned identity without reloading', async ({ page }) => {
  await fixture(page)
  const original = { ...emptyAccount(), id: 1, access_key_id: 'LTAItest', secret_configured: true, region_id: 'cn-beijing', instance_id: 'i-current', remark: '测试实例', max_traffic: 20 }
  let config = { ...defaultConfig(), threshold_action: 'notify_only', accounts: [original] }
  const now = new Date().toISOString()
  await page.route('**/api/v1/config', async route => {
    if (route.request().method() === 'PUT') {
      const submitted = route.request().postDataJSON() as typeof config
      config = { ...submitted, accounts: submitted.accounts.map(item => ({ ...item, id: item.id || 2, secret_configured: true, access_key_secret: undefined })) }
      await route.fulfill({ json: { success: true } })
      return
    }
    await route.fulfill({ json: config })
  })
  await page.route('**/api/v1/status', route => route.fulfill({ json: {
    accounts: config.accounts.map(item => ({ id: item.id, account: 'LTAItes***', remark: item.remark, region: item.region_id, region_name: '北京', flow_total: 20, flow_used: 1, percentage: 5, threshold: 95, over_threshold: false, instance_status: 'Running', last_updated: now, stale: false, traffic_pool_id: 'pool-1', traffic_pool_class: 'china', traffic_pool_instance_count: config.accounts.length, traffic_pool_quota_conflict: false, traffic_updated_at: now, traffic_stale: false })), system_last_run: now,
  } }))
  await page.route('**/api/v1/accounts/instance-addresses', route => route.fulfill({ json: { instances: config.accounts.map(item => ({ account_id: item.id, access_key_id: item.access_key_id, region_id: item.region_id, instance_id: item.instance_id, public_ipv4: item.id === 2 ? '198.51.100.20' : '', ipv6: '', observed_at: now, observed: true, stale: false })) } }))
  await page.route('**/api/v1/accounts/discover', route => route.fulfill({ json: { instances: [{ instance_id: 'i-new', instance_name: '新导入实例', region_id: 'cn-beijing', status: 'Running', charge_type: 'spot' }], next_token: '' } }))
  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '实例', exact: true }).click()
  await page.getByRole('button', { name: '从阿里云导入' }).click()
  const wizard = page.getByRole('dialog', { name: '从阿里云导入实例' })
  await wizard.getByRole('button', { name: '查询实例' }).click()
  await wizard.getByRole('checkbox', { name: '选择 新导入实例' }).check()
  await wizard.getByRole('button', { name: '下一步：确认导入' }).click()
  await wizard.getByRole('button', { name: '加入设置草稿' }).click()
  await page.getByRole('dialog', { name: '系统设置' }).getByRole('button', { name: '保存更改' }).click()
  await expect(page.getByRole('dialog', { name: '系统设置' })).toHaveCount(0)
  await expect(page.locator('.account-card').filter({ hasText: '新导入实例' }).getByText('198.51.100.20')).toBeVisible()
  expect(config.accounts[1].id).toBe(2)
  expect(await page.evaluate(() => performance.getEntriesByType('navigation').length)).toBe(1)
})

test('saved configuration readback failure is reported without calling the save a failure', async ({ page }) => {
  await fixture(page)
  let saved = false
  await page.route('**/api/v1/config', route => {
    if (route.request().method() === 'PUT') { saved = true; return route.fulfill({ json: { success: true } }) }
    if (saved) return route.fulfill({ status: 500, json: { error: { code: 'config_failed', message: '读取失败' } } })
    return route.fulfill({ json: defaultConfig() })
  })
  await page.goto('/')
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await page.getByRole('button', { name: '保存更改' }).click()
  await expect(page.getByText('配置已保存，但读取最新配置失败；请刷新页面后继续')).toBeVisible()
  await expect(page.getByRole('dialog', { name: '系统设置' })).toBeVisible()
})

test('an old server or proxy returning HTML for addresses does not break the dashboard', async ({ page }) => {
  await fixture(page)
  await page.route('**/api/v1/accounts/instance-addresses', route => route.fulfill({ status: 200, contentType: 'text/html', body: '<html>fallback</html>' }))
  await page.goto('/')
  await expect(page.getByRole('heading', { name: '资源控制台' })).toBeVisible()
  await expect(page.getByText('实例地址待同步')).toBeVisible()
  await page.getByRole('button', { name: '设置', exact: true }).click()
  await expect(page.getByRole('dialog', { name: '系统设置' })).toBeVisible()
})

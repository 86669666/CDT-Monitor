import { expect, test } from '@playwright/test'
import { spawn, type ChildProcess } from 'node:child_process'
import { createServer } from 'node:http'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { join } from 'node:path'

const runtime = process.env.CDT_CORE_RUNTIME

test('real SQLite HTTP worker crash exposes uncertainty and explicit review never replays', async ({ page, context }, testInfo) => {
  test.skip(!runtime, 'requires built production HTTP/worker subprocess helper')
  const root = await mkdtemp(join(runtime!, 'browser-data-'))
  let child: ChildProcess | undefined
  let cloudControls = 0
  let cloudReads = 0
  let notifications = 0
  let cloudStatus = 'Running'
  let cloudTraffic = 200
  let pendingControl: (() => void) | undefined
  const accepted = new Promise<void>(resolve => { pendingControl = resolve })
  const cloud = createServer((req, res) => {
    if (req.url === '/traffic') { cloudReads++; res.end(JSON.stringify(cloudTraffic)) }
    else if (req.url === '/status') res.end(JSON.stringify(cloudStatus))
    else if (req.url === '/notify') { notifications++; req.resume(); res.end('ok') }
    else if (req.url === '/control') { req.resume(); cloudControls++; pendingControl?.() }
    else { res.statusCode = 404; res.end() }
  })
  await new Promise<void>(resolve => cloud.listen(0, '127.0.0.1', resolve))
  const address = cloud.address() as { port: number }
  const cloudURL = `http://127.0.0.1:${address.port}`
  const launch = async () => {
    const ready = join(root, `ready-${Date.now()}`)
    child = spawn(join(runtime!, 'httpapi.test'), ['-test.run=^TestCoreRuntimeProcessHelper$', '-test.v'], {
      env: { ...process.env, CDT_CORE_PROCESS_HELPER: '1', CDT_CORE_DATA: root, CDT_CORE_CLOUD: cloudURL, CDT_CORE_READY: ready },
      stdio: ['ignore', 'pipe', 'pipe'],
    })
    let output = ''
    child.stdout?.on('data', data => { output += data.toString() })
    child.stderr?.on('data', data => { output += data.toString() })
    for (let i = 0; i < 100; i++) {
      if (child.exitCode !== null) throw new Error(`helper exited: ${output}`)
      try { return await readFile(ready, 'utf8') } catch { await new Promise(resolve => setTimeout(resolve, 50)) }
    }
    throw new Error('helper readiness timeout')
  }
  const stop = async (signal: NodeJS.Signals) => {
    if (!child || child.exitCode !== null || child.signalCode !== null) return
    const exited = new Promise<void>(resolve => child!.once('exit', () => resolve()))
    child.kill(signal); await exited
  }
  try {
    let url = await launch()
    // Preparation and requests use the actual server; no page.route/response fixture.
    const setup = await context.request.post(`${url}/api/v1/setup`, { data: {
      admin_password: 'Browser-Test-password', traffic_threshold: 95, shutdown_mode: 'KeepCharging', threshold_action: 'stop_and_notify', api_interval: 600,
      notifications: { webhook: { enabled: true, url: `${cloudURL}/notify`, method: 'POST' } },
      timezone: 'Asia/Shanghai', accounts: [{ access_key_id: 'LTAIbrowser', access_key_secret: 'test-only-secret', region_id: 'cn-hongkong', instance_id: 'i-browser-original', max_traffic: 200, site_type: 'china', remark: 'Restart verification' }],
    } })
    expect(setup.status()).toBe(201)
    const csrf = (await setup.json()).csrf_token
    // Keep the current-minute deduplication key stable through the rapid restart.
    if (new Date().getSeconds() > 50) await new Promise(resolve => setTimeout(resolve, (61 - new Date().getSeconds()) * 1000))
    const refresh = await context.request.post(`${url}/api/v1/accounts/1/refresh`, { headers: { 'X-CDT-CSRF': csrf } })
    expect(refresh.status()).toBe(202)
    const job = await refresh.json()
    await Promise.race([accepted, new Promise((_, reject) => setTimeout(() => reject(new Error('fake cloud never accepted control')), 8000))])
    const crashAt = Date.now()
    await stop('SIGKILL')
    url = await launch()
    const restartMs = Date.now() - crashAt
    expect(restartMs).toBeLessThan(120000)
    const recovered = await context.request.get(`${url}/api/v1/jobs/${job.id}`)
    expect((await recovered.json()).status).toBe('interrupted')
    await page.goto(url)
    await expect(page.getByRole('heading', { name: '资源控制台' })).toBeVisible()
    await expect(page.getByText('自动控制已暂停：', { exact: false })).toBeVisible()
    cloudTraffic = 201
    const readsBefore = cloudReads
    const newRefreshResponse = page.waitForResponse(r => r.url().endsWith('/api/v1/accounts/1/refresh') && r.request().method() === 'POST')
    await page.getByRole('button', { name: '刷新实例', exact: true }).click()
    const newResponse = await newRefreshResponse
    expect(newResponse.status()).toBe(202)
    const newJob = await newResponse.json()
    expect(newJob.id).not.toBe(job.id)
    await expect.poll(async () => (await (await context.request.get(`${url}/api/v1/jobs/${newJob.id}`)).json()).status).toBe('completed')
    await expect(page.getByText('实例状态已刷新', { exact: true })).toBeVisible()
    expect(cloudReads).toBeGreaterThan(readsBefore)
    expect(cloudControls).toBe(1)
    expect(notifications).toBe(0)
    const freshStatus = await (await context.request.get(`${url}/api/v1/status`, { headers: { 'Cache-Control': 'no-cache' } })).json()
    expect(freshStatus.accounts[0].flow_used).toBe(201)
    expect((await (await context.request.get(`${url}/api/v1/jobs/${job.id}`)).json()).status).toBe('interrupted')
    await page.screenshot({ path: testInfo.outputPath('real-readonly-refresh.png'), fullPage: true })
    await page.getByRole('button', { name: '中断任务核对', exact: true }).click()
    const dialog = page.getByRole('dialog', { name: '中断任务与不明结果' })
    await expect(dialog).toBeVisible()
    await expect(dialog.getByText('i-browser-original', { exact: false })).toBeVisible()
    await page.screenshot({ path: testInfo.outputPath('real-recovery-desktop.png'), fullPage: true })
    await page.setViewportSize({ width: 390, height: 844 })
    await expect(dialog).toBeVisible()
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true)
    await page.screenshot({ path: testInfo.outputPath('real-recovery-mobile.png'), fullPage: true })
    cloudStatus = 'Stopped'; cloudTraffic = 1
    // Resolve each explicit pending job/action; the handler is not a replay action.
    for (let i = 0; i < 8; i++) {
      const buttons = dialog.getByRole('button', { name: '核对此记录', exact: true })
      if (await buttons.count() === 0) break
      await buttons.first().click()
      const complete = dialog.getByRole('button', { name: '完成核对，不重发', exact: true })
      await expect(complete).toBeDisabled()
      await dialog.getByLabel('核对说明', { exact: true }).fill('Verified original target stopped in test cloud')
      await dialog.getByRole('checkbox').check()
      await complete.click()
      await expect(complete).toHaveCount(0)
    }
    expect(cloudControls).toBe(1)
    await expect(dialog.getByText('没有待核对记录')).toBeVisible()
    await page.screenshot({ path: testInfo.outputPath('real-recovery-reviewed.png'), fullPage: true })
    await dialog.getByRole('button', { name: '关闭核对窗口' }).click()
    await expect(page.getByText('自动控制已暂停：', { exact: false })).toHaveCount(0)
    await writeFile(testInfo.outputPath('real-chain.json'), JSON.stringify({ job_id: job.id, new_readonly_job_id: newJob.id, new_job_status: 'completed', provider_read_delta: cloudReads - readsBefore, persisted_traffic: freshStatus.accounts[0].flow_used, notification_calls: notifications, cloud_control_calls: cloudControls, crash_restart_ms: restartMs, backend: 'production app.OpenData + HTTP + SQLite + worker', cloud_boundary: 'loopback fake accepted control then disconnected', fixtures: false }, null, 2))
  } finally {
    await stop('SIGTERM')
    cloud.closeAllConnections()
    await new Promise<void>(resolve => cloud.close(() => resolve()))
    await rm(root, { recursive: true, force: true })
  }
})

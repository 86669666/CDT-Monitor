import type { APIErrorBody, Job, JobStatus } from './types'

export const CSRF_COOKIE = 'cdt_csrf'
export const CSRF_HEADER = 'X-CDT-CSRF'

export class APIError extends Error {
  status: number
  code: string
  constructor(status: number, code: string, message: string) {
    super(message)
    this.status = status
    this.code = code
  }
}

function cookie(name: string) {
  const prefix = `${name}=`
  const value = document.cookie.split('; ').find((part) => part.startsWith(prefix))
  return value ? decodeURIComponent(value.slice(prefix.length)) : ''
}

function errorDetail(body: unknown): { code: string; message?: string } | undefined {
  if (!body || typeof body !== 'object' || !('error' in body)) return undefined
  const detail = (body as APIErrorBody).error
  if (!detail || typeof detail !== 'object') return undefined
  return detail
}

export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers)
  if (init.body && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json')
  if (init.method && init.method !== 'GET' && init.method !== 'HEAD') {
    const csrf = cookie(CSRF_COOKIE)
    if (csrf) headers.set(CSRF_HEADER, csrf)
  }
  const response = await fetch(path, { ...init, headers, credentials: 'same-origin' })
  if (response.status === 204) return undefined as T
  const body = await response.json().catch(() => ({}))
  if (!response.ok) {
    const detail = errorDetail(body)
    throw new APIError(response.status, detail?.code ?? 'request_failed', detail?.message ?? `HTTP ${response.status}`)
  }
  return body as T
}

export async function fetchLatestReleaseFromGitHub() {
  const controller = new AbortController()
  const timeout = window.setTimeout(() => controller.abort(), 4_000)
  try {
    const response = await fetch('https://api.github.com/repos/wang4386/CDT-Monitor/releases/latest', {
      headers: { Accept: 'application/vnd.github+json' },
      credentials: 'omit',
      cache: 'no-store',
      signal: controller.signal,
    })
    const payload = await response.json().catch(() => null) as { tag_name?: unknown } | null
    if (!response.ok) throw new Error(`GitHub API 请求失败（HTTP ${response.status}）`)
    if (!payload || typeof payload.tag_name !== 'string' || !payload.tag_name.trim()) throw new Error('GitHub Release 响应无版本号')
    return payload.tag_name
  } finally {
    window.clearTimeout(timeout)
  }
}

export const JOB_FAILED_USER_MESSAGE = '任务失败，详见日志'

export async function waitForJob(jobId: string, onProgress?: (status: JobStatus) => void) {
  const deadline = Date.now() + 70_000
  while (Date.now() < deadline) {
    const job = await api<Job>(`/api/v1/jobs/${jobId}`)
    onProgress?.(job.status)
    if (job.status === 'completed') return job
    if (job.status === 'failed') throw new Error(JOB_FAILED_USER_MESSAGE)
    await new Promise((resolve) => window.setTimeout(resolve, 900))
  }
  throw new Error('任务仍在后台执行，请稍后刷新')
}

import type { Account, AccountSummary } from './types'

export function trafficClass(region: string): 'china' | 'international' {
  return region.startsWith('cn-') && region !== 'cn-hongkong' ? 'china' : 'international'
}

export function defaultTrafficQuota(region: string): number {
  return trafficClass(region) === 'china' ? 20 : 200
}

export function trafficClassLabel(region: string): string {
  return trafficClass(region) === 'china' ? '国内（中国内地）' : '国际（非中国内地）'
}

function poolKey(account: Account): string {
  return `${account.access_key_id.trim()}\0${trafficClass(account.region_id)}`
}

// Joining an existing pool inherits its quota. Editing a quota edits the pool.
export function updateTrafficAccount(accounts: Account[], index: number, next: Account): Account[] {
  const previous = accounts[index]
  const key = poolKey(next)
  const moved = poolKey(previous) !== key
  const peer = next.access_key_id.trim() && accounts.find((account, i) => i !== index && poolKey(account) === key)
  const quota = moved ? (peer ? peer.max_traffic : defaultTrafficQuota(next.region_id)) : next.max_traffic
  return accounts.map((account, i) => {
    if (i === index) return { ...next, max_traffic: quota }
    return next.access_key_id.trim() && poolKey(account) === key ? { ...account, max_traffic: quota } : account
  })
}

export function totalPoolTraffic(accounts: AccountSummary[]): number {
  const seen = new Set<string>()
  return accounts.reduce((total, account) => {
    // Older servers have no safe identity to group by; never use masked AKs.
    const key = account.traffic_pool_id || `instance:${account.id}`
    if (seen.has(key)) return total
    seen.add(key)
    return total + account.flow_used
  }, 0)
}

export type TrafficOverview = { kind: 'china' | 'international'; pools: number; total: number; used: number; remaining: number; stale: boolean; conflict: boolean }

export function trafficOverviews(accounts: AccountSummary[]): TrafficOverview[] {
  return (['china', 'international'] as const).map(kind => {
    const pools = new Map<string, AccountSummary>()
    let stale = false, conflict = false
    for (const account of accounts) {
      if ((account.traffic_pool_class || trafficClass(account.region)) !== kind) continue
      const key = account.traffic_pool_id
      if (!key) { stale = true; continue } // Cannot safely total an unidentified pool.
      const previous = pools.get(key)
      if (previous && previous.flow_total !== account.flow_total) conflict = true
      if (!previous || Date.parse(account.traffic_updated_at || '') > Date.parse(previous.traffic_updated_at || '')) pools.set(key, account)
      stale ||= account.traffic_stale !== false
      conflict ||= !!account.traffic_pool_quota_conflict
    }
    const rows = [...pools.values()]
    return { kind, pools: rows.length, total: rows.reduce((n,a)=>n+a.flow_total,0), used: rows.reduce((n,a)=>n+a.flow_used,0), remaining: rows.reduce((n,a)=>n+Math.max(a.flow_total-a.flow_used,0),0), stale, conflict }
  })
}

export function instanceChargeLabel(kind: AccountSummary['instance_charge_type']): string {
  return kind === 'spot' ? '抢占式' : kind === 'subscription' ? '包年包月' : kind === 'pay_as_you_go' ? '按量付费' : '类型待识别'
}

export function instanceIdentity(instance: { region_id: string; instance_id: string }): string {
  return `${instance.region_id}\0${instance.instance_id}`
}

export function mergeDiscoveredInstances<T extends { region_id: string; instance_id: string }>(previous: T[], incoming: T[]): T[] {
  return [...new Map([...previous, ...incoming].map(row => [instanceIdentity(row), row])).values()]
}

export function prepareInstanceImport(
  current: Account[], rows: import('./types').DiscoveredInstance[], credential: import('./types').ImportCredential,
  template: Account, limit: number,
): Account[] {
  const known = new Set(current.map(instanceIdentity))
  const unique = mergeDiscoveredInstances([], rows).filter(row => !known.has(instanceIdentity(row)))
  if (!unique.length) throw new Error('所选实例已在当前设置中，无需重复导入')
  if (current.length + unique.length > limit) throw new Error(`最多配置 ${limit} 个实例，请减少选择后重试`)
  return unique.map(row => {
    const peer = current.find(a => a.access_key_id === credential.access_key_id && trafficClass(a.region_id) === trafficClass(row.region_id))
    return { ...template, id: 0, access_key_id: credential.access_key_id, access_key_secret: credential.access_key_secret,
      secret_configured: true, site_type: credential.site_type, instance_id: row.instance_id, region_id: row.region_id,
      remark: Array.from(row.instance_name || row.instance_id).slice(0, 64).join(''), max_traffic: peer?.max_traffic ?? defaultTrafficQuota(row.region_id),
      schedule_enabled: false, keep_alive: false, daily_report: false }
  })
}

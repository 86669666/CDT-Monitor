import { useEffect, useRef, useState } from 'react'
import { createPortal } from 'react-dom'
import { ArrowLeft, Check, Cloud, LoaderCircle, Search, X } from 'lucide-react'
import { api } from './api'
import { emptyAccount, MAX_ACCOUNTS } from './types'
import type { Account, Config, DiscoveredInstance, DiscoveryPage, ImportCredential } from './types'
import { instanceChargeLabel, instanceIdentity, mergeDiscoveredInstances, prepareInstanceImport, trafficClassLabel } from './traffic'

type Props = { config: Config; regions: { value: string; label: string }[]; onImport: (accounts: Account[]) => void; onClose: () => void }
type Query = { credential: ImportCredential; region: string }

export default function InstanceImportWizard({ config, regions, onImport, onClose }: Props) {
  const sources = [...new Map(config.accounts.filter(a => a.id > 0 && a.secret_configured && a.access_key_id).map(a => [a.access_key_id, a])).values()]
  const [source, setSource] = useState(sources[0] ? String(sources[0].id) : 'new')
  const [region, setRegion] = useState(sources[0]?.region_id || 'cn-hongkong')
  const [key, setKey] = useState('')
  const [secret, setSecret] = useState('')
  const [site, setSite] = useState<'china' | 'international'>('china')
  const [step, setStep] = useState(1)
  const [rows, setRows] = useState<DiscoveredInstance[]>([])
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [nextToken, setNextToken] = useState('')
  const [pages, setPages] = useState(0)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [query, setQuery] = useState<Query | null>(null)
  const request = useRef<AbortController | null>(null)
  const generation = useRef(0)
  const panel = useRef<HTMLElement>(null)
  const seenTokens = useRef(new Set<string>())
  const known = new Set(config.accounts.map(instanceIdentity))
  const capacity = Math.max(0, MAX_ACCOUNTS - config.accounts.length)
  const picked = rows.filter(row => selected.has(instanceIdentity(row)) && !known.has(instanceIdentity(row)))
  const preview = query && picked.length ? preparePreview() : []

  function preparePreview() {
    try { return prepareInstanceImport(config.accounts, picked, query!.credential, emptyAccount(), MAX_ACCOUNTS) } catch { return [] }
  }
  useEffect(() => {
    const previous = document.activeElement as HTMLElement | null
    panel.current?.querySelector<HTMLElement>('select,button')?.focus()
    return () => { generation.current++; request.current?.abort(); previous?.focus() }
  }, [])

  function reset() {
    generation.current++; request.current?.abort(); setBusy(false); setRows([]); setSelected(new Set()); setNextToken(''); setPages(0); setQuery(null); setError(''); seenTokens.current.clear()
  }
  function credential(): ImportCredential {
    if (source === 'new') return { access_key_id: key.trim(), access_key_secret: secret.trim(), site_type: site }
    const a = sources.find(a => String(a.id) === source)
    if (!a) throw new Error('原凭据不可用，请重新选择')
    return { access_key_id: a.access_key_id, access_key_secret: a.access_key_secret || '', source_account_id: a.access_key_secret ? undefined : a.id, site_type: a.site_type }
  }
  async function load(more = false) {
    const ticket = ++generation.current
    request.current?.abort()
    const abort = new AbortController(); request.current = abort
    setBusy(true); setError('')
    try {
      const q = more && query ? query : { credential: credential(), region }
      const token = more ? nextToken : ''
      const result = await api<DiscoveryPage>('/api/v1/accounts/discover', { method: 'POST', signal: abort.signal,
        body: JSON.stringify({ source_account_id: q.credential.source_account_id || 0, access_key_id: q.credential.access_key_id, access_key_secret: q.credential.access_key_secret, region_id: q.region, next_token: token }) })
      if (ticket !== generation.current) return
      if (result.next_token && seenTokens.current.has(result.next_token)) throw new Error('分页游标重复，请返回上一步重新查询')
      if (result.next_token) seenTokens.current.add(result.next_token)
      setRows(previous => mergeDiscoveredInstances(more ? previous : [], result.instances)); setNextToken(result.next_token)
      setPages(n => more ? n + 1 : 1); setQuery(q); setStep(2)
      if (!more) setSelected(new Set())
    } catch (e) {
      if (ticket === generation.current && !abort.signal.aborted) setError(e instanceof Error ? e.message : '查询失败，请重试')
    } finally { if (ticket === generation.current) setBusy(false) }
  }
  function toggle(row: DiscoveredInstance) {
    const id = instanceIdentity(row)
    if (known.has(id)) return
    setSelected(previous => { const next = new Set(previous); if (next.has(id)) next.delete(id); else if (picked.length < capacity) next.add(id); return next })
  }
  function finish() {
    if (!query) return
    try {
      const imports = prepareInstanceImport(config.accounts, picked, query.credential, emptyAccount(), MAX_ACCOUNTS)
      onImport(imports)
    } catch (e) { setError(e instanceof Error ? e.message : '导入失败') }
  }
  const availableRegions = regions.some(r => r.value === region) ? regions : [...regions, {value: region, label: region}]
  return createPortal(<div className="modal-layer modal-layer--nested import-layer" role="dialog" aria-modal="true" aria-label="从阿里云导入实例" onKeyDown={e => {
    if (e.key === 'Escape') { e.stopPropagation(); onClose() }
    if (e.key === 'Tab') {
      const controls = [...(panel.current?.querySelectorAll<HTMLElement>('button:not(:disabled),input:not(:disabled),select:not(:disabled),[tabindex="0"]') || [])]
      const first = controls[0], last = controls[controls.length - 1]
      if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last?.focus() }
      if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first?.focus() }
    }
  }}>
    <div className="modal-scrim" onClick={onClose} />
    <section ref={panel} className="import-panel glass-card">
      <header><div><p className="eyebrow">IMPORT FROM ALIYUN</p><h2>从阿里云导入实例</h2></div><button className="icon-button" aria-label="关闭导入向导" onClick={onClose}><X /></button></header>
      <ol className="import-steps">{['选择凭据与地域', '选择实例', '确认导入'].map((label,i)=><li key={label} aria-current={step===i+1?'step':undefined} className={step>=i+1?'active':''}><b>{i+1}</b>{label}</li>)}</ol>
      <div className="import-content">
        {step === 1 && <>
          <p className="muted">查询指定地域下有权访问的 ECS 实例，选择后加入监控设置。</p>
          <div className="field"><label htmlFor="import-source">AccessKey 来源</label><select id="import-source" value={source} disabled={busy} onChange={e=>{reset(); setSource(e.target.value); const a=sources.find(a=>String(a.id)===e.target.value); if(a)setRegion(a.region_id)}}>{sources.map(a=><option key={a.id} value={a.id}>{a.remark || a.region_id} · {a.access_key_id.slice(0,7)}…（已配置）</option>)}<option value="new">填写新的 AccessKey</option></select></div>
          {source === 'new' ? <div className="form-grid"><div className="field"><label htmlFor="import-key">AccessKey ID</label><input id="import-key" autoComplete="off" maxLength={64} value={key} disabled={busy} onChange={e=>{reset();setKey(e.target.value)}} /></div><div className="field"><label htmlFor="import-secret">AccessKey Secret</label><input id="import-secret" type="password" autoComplete="new-password" maxLength={128} value={secret} disabled={busy} onChange={e=>{reset();setSecret(e.target.value)}} /></div><div className="field"><label htmlFor="import-site">账号站点</label><select id="import-site" value={site} disabled={busy} onChange={e=>{reset();setSite(e.target.value as 'china'|'international')}}><option value="china">中国站</option><option value="international">国际站</option></select></div></div> : <p className="inline-hint">复用已配置凭据，无需再次填写 Secret。</p>}
          <div className="field"><label htmlFor="import-region">查询地域</label><select id="import-region" value={region} disabled={busy} onChange={e=>{reset();setRegion(e.target.value)}}>{availableRegions.map(r=><option key={r.value} value={r.value}>{r.label}</option>)}</select></div>
          <p className="inline-hint">查询不会修改设置。可分次导入不同地域的实例。</p>
        </>}
        {step === 2 && <>
          <div className="import-list-heading"><p>已加载 {rows.length} 台 · 已选 {picked.length} 台 · 还可添加 {capacity} 台</p><button className="button button--secondary button--small" disabled={busy || !rows.some(r=>!known.has(instanceIdentity(r)))} onClick={()=>setSelected(new Set(rows.filter(r=>!known.has(instanceIdentity(r))).slice(0,capacity).map(instanceIdentity)))}>选择可添加实例（最多 {capacity} 台）</button></div>
          {!rows.length && <div className="subtle-empty"><Cloud />该地域未查到实例，可返回更换地域或凭据</div>}
          <div className="import-instance-list">{rows.map(row=>{const id=instanceIdentity(row), exists=known.has(id);return <label key={id} className={`import-instance ${exists?'import-instance--existing':''}`}><input type="checkbox" aria-label={`选择 ${row.instance_name || row.instance_id}`} checked={selected.has(id)&&!exists} disabled={exists||busy||(!selected.has(id)&&picked.length>=capacity)} onChange={()=>toggle(row)} /><div><b>{row.instance_name || row.instance_id}</b><code>{row.instance_id}</code><span>{row.region_id} · {instanceChargeLabel(row.charge_type)} · {row.status==='Running'?'运行中':row.status==='Stopped'?'已停止':row.status}</span></div><small>{exists?'已监控 / 已在草稿':selected.has(id)?'已选择':''}</small></label>})}</div>
          {nextToken && pages < 20 && <button className="button button--secondary import-more" disabled={busy} onClick={()=>void load(true)}>{busy?<LoaderCircle className="spin"/>:<Search/>}加载更多实例</button>}
          {nextToken && pages >= 20 && <p className="inline-hint">本次已达到 20 页查询上限，仍有实例未加载。可先导入已选实例，其他实例使用手动添加。</p>}
          {!nextToken && rows.length > 0 && <p className="inline-hint">该地域的查询结果已全部加载。</p>}
        </>}
        {step === 3 && <>
          <p>将 {picked.length} 台实例加入当前设置草稿：</p>
          <div className="import-instance-list">{preview.map(a=><div className="import-instance" key={instanceIdentity(a)}><Check size={18}/><div><b>{a.remark}</b><code>{a.instance_id}</code><span>{trafficClassLabel(a.region_id)}共享池 · {a.max_traffic} GB/月</span></div></div>)}</div>
          <p className="inline-hint">同一账号、同类地域共用额度；已有池沿用当前额度。定时开关机、保活和日报默认关闭。</p>
          <p className="import-confirm-note">加入草稿后，还需点击控制台设置的“保存更改”才会生效。保存后遵循现有流量阈值规则：{config.threshold_action==='notify_only'?'仅通知':'达到阈值会停机并通知'}。</p>
        </>}
        {error && <p className="import-error" role="alert">{error}</p>}
      </div>
      <footer><button className="button button--secondary" onClick={()=>{if(step===1)onClose();else if(step===2){reset();setStep(1)}else{setError('');setStep(2)}}}>{step===1?'取消':<><ArrowLeft/>上一步</>}</button>
        {step===1?<button className="button button--primary" disabled={busy||(source==='new'&&(!key.trim()||!secret.trim()))} onClick={()=>void load()}>{busy?<LoaderCircle className="spin"/>:<Search/>}{busy?'正在查询…':'查询实例'}</button>:step===2?<button className="button button--primary" disabled={busy||!picked.length||picked.length>capacity} onClick={()=>{setError('');setStep(3)}}>下一步：确认导入</button>:<button className="button button--primary" disabled={!preview.length} onClick={finish}><Check/>加入设置草稿</button>}
      </footer>
    </section>
  </div>, document.body)
}

import { useEffect, useState } from 'react'
import { api } from './api'

type Record = { kind: 'job' | 'action' | 'notification'; id: string; account_id: number; status: string; detail: string; target: string }

export function RecoveryPanel({ onClose, onResolved }: { onClose: () => void; onResolved: () => void }) {
  const [records, setRecords] = useState<Record[]>([])
  const [selected, setSelected] = useState<Record | null>(null)
  const [note, setNote] = useState('')
  const [reviewed, setReviewed] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const load = async () => {
    try { setRecords((await api<{ records: Record[] }>('/api/v1/recovery')).records) }
    catch { setError('待核对记录加载失败，请关闭后重试') }
  }
  useEffect(() => { void load() }, [])
  const resolve = async () => {
    if (!selected || !reviewed || !note.trim()) return
    setBusy(true); setError('')
    try {
      await api(`/api/v1/recovery/${selected.kind}/${encodeURIComponent(selected.id)}/resolve`, { method: 'POST', body: JSON.stringify({ reviewed, note: note.trim() }) })
      setSelected(null); setNote(''); setReviewed(false)
      await load(); onResolved()
    } catch (e) { setError(e instanceof Error ? e.message : '核对失败') }
    finally { setBusy(false) }
  }
  return <div className="modal-layer"><div className="modal-scrim" onClick={busy ? undefined : onClose} /><section className="glass-card recovery-modal" role="dialog" aria-modal="true" aria-labelledby="recovery-title">
    <h2 id="recovery-title">中断任务与不明结果</h2>
    <p>这些请求可能已在远端生效。请先核对原目标及实际结果；完成核对仅解除该记录的自动控制阻断，不会重发旧请求。</p>
    {error && <p role="alert" className="error-text">{error}</p>}
    {!records.length && !error && <p>没有待核对记录</p>}
    <div className="recovery-records">{records.map(record => <article className="recovery-record" key={`${record.kind}:${record.id}`}>
      <strong>{record.kind === 'notification' ? '通知投递结果不明 · 已停止重发' : record.status === 'submitted' ? '请求已受理 · 等待状态核对' : '任务中断 · 结果不明'}</strong>
      <p>账号 {record.account_id || '全局'} · {record.kind === 'action' ? '动作尝试' : '记录'} <code>{record.id}</code></p>
      <p>{record.detail}</p>
      {record.target ? <p>原目标：{targetLabel(record.target)}</p> : record.kind !== 'notification' && <p>旧记录缺少目标身份，请根据原任务核对，不能用当前实例代替。</p>}
      {record.kind !== 'notification' && <button className="button" disabled={busy} onClick={() => { setSelected(record); setNote(''); setReviewed(false) }}>核对此记录</button>}
    </article>)}</div>
    {selected && <fieldset className="recovery-review"><legend>核对记录 {selected.id}</legend>
      <label>核对说明<input aria-label="核对说明" maxLength={256} value={note} onChange={e => setNote(e.target.value)} /></label>
      <label><input type="checkbox" checked={reviewed} onChange={e => setReviewed(e.target.checked)} />我已核对原目标与远端结果，允许后续自动控制</label>
      <button className="button" disabled={busy || !reviewed || !note.trim()} onClick={() => void resolve()}>完成核对，不重发</button>
    </fieldset>}
    <button className="button" disabled={busy} onClick={onClose}>关闭核对窗口</button>
  </section></div>
}

function targetLabel(raw: string) {
  try { const t = JSON.parse(raw); return `${t.region} / ${t.instance} / ${t.action} / ${t.shutdown_mode}` }
  catch { return '身份记录无法解析，请人工核对原任务' }
}

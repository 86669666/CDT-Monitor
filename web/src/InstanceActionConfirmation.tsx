import { useEffect, useRef } from 'react'
import { createPortal } from 'react-dom'
import { AlertTriangle, Play, Power } from 'lucide-react'
import type { AccountSummary } from './types'

export default function InstanceActionConfirmation({ account, instanceId, action, onCancel, onConfirm }: {
  account: AccountSummary; instanceId: string; action: 'start' | 'stop'; onCancel: () => void; onConfirm: () => void
}) {
  const cancel = useRef<HTMLButtonElement>(null)
  const confirm = useRef<HTMLButtonElement>(null)
  const label = action === 'start' ? '开机' : '关机'
  useEffect(() => {
    const previous = document.activeElement as HTMLElement | null
    cancel.current?.focus()
    return () => previous?.focus()
  }, [])
  return createPortal(<div className="modal-layer" role="alertdialog" aria-modal="true" aria-labelledby="instance-action-title" aria-describedby="instance-action-description" onKeyDown={e=>{
    if(e.key==='Escape'){e.preventDefault();e.stopPropagation();onCancel()}
    if(e.key==='Tab'){
      if(e.shiftKey && document.activeElement===cancel.current){e.preventDefault();confirm.current?.focus()}
      else if(!e.shiftKey && document.activeElement===confirm.current){e.preventDefault();cancel.current?.focus()}
    }
  }}>
    <div className="modal-scrim" onClick={onCancel}/>
    <section className={`glass-card action-confirm action-confirm--${action}`}>
      <div className="action-confirm__icon">{action==='stop'?<AlertTriangle/>:<Play/>}</div>
      <h2 id="instance-action-title">确认{label}？</h2>
      <div className="action-confirm__target"><strong>{account.remark || account.account}</strong><span>{account.region_name || account.region}</span>{instanceId && <code>{instanceId}</code>}</div>
      <p id="instance-action-description">{action==='stop'?'关机后，该实例上运行的服务会中断。':'确认向此实例发送开机指令？'}</p>
      <footer><button ref={cancel} className="button button--secondary" onClick={onCancel}>取消</button><button ref={confirm} className="button button--primary" onClick={onConfirm}>{action==='stop'?<Power/>:<Play/>}确认{label}</button></footer>
    </section>
  </div>,document.body)
}
